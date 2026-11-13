//! Which PHP-FPM pool serves a path application (cadrage §5bis): the pools (`listen`) and the web servers' sites
//! (nginx `root` + `fastcgi_pass`, Apache `DocumentRoot` + `SetHandler proxy:` / `ProxyPassMatch fcgi:`) are **read
//! from their files only**, never by a command. A site whose document root is the application or under it, and that
//! passes PHP to a pool, gives the application the PHP version of that pool.

use serde_json::{Value, json};

use super::files::{self, Files};

/// Where a pool listens: a Unix socket, or a TCP port (any address).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Listen {
    Socket(String),
    Port(u16),
}

impl Listen {
    /// `/run/php/php8.2-fpm.sock`, `unix:/run/…`, `127.0.0.1:9000`, `[::1]:9000`, `9000`.
    fn parse(value: &str) -> Option<Self> {
        let value = value.trim().trim_matches('"').trim_matches('\'');
        let value = value.strip_prefix("unix:").unwrap_or(value);
        if value.starts_with('/') {
            return Some(Self::Socket(value.to_owned()));
        }
        value.rsplit(':').next()?.parse().ok().map(Self::Port)
    }
}

/// A pool of a PHP-FPM service (`php8.2-fpm` on Debian, `php-fpm` on RHEL, `php83-php-fpm` with Remi).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pool {
    pub listen: Listen,
    pub service: String,
    /// `8.2`, when the layout tells it (Debian, Remi); the default `php-fpm` of RHEL does not.
    pub branch: Option<String>,
}

/// The document roots of a site, and the FastCGI targets it passes PHP to.
type Site = (Vec<String>, Vec<Listen>);

/// A document root whose PHP goes to a pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Served {
    pub root: String,
    pub pool: Pool,
}

fn configs(files: &dyn Files, dir: &str, suffix: &str) -> Vec<String> {
    files
        .list(dir)
        .into_iter()
        .filter(|name| name.ends_with(suffix) && !name.starts_with('.'))
        .filter_map(|name| files::text(files, &files::join(dir, &name)))
        .collect()
}

/// The `listen` of each `[pool]` of a pool file (`$pool` replaced by its name, comments dropped).
fn listens(text: &str) -> Vec<Listen> {
    let mut pool = String::new();
    let mut found = Vec::new();
    for line in text.lines() {
        let line = line.split([';', '#']).next().unwrap_or("").trim();
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            pool = name.trim().to_owned();
        } else if let Some((key, value)) = line.split_once('=') {
            if key.trim() == "listen" {
                found.extend(Listen::parse(&value.replace("$pool", &pool)));
            }
        }
    }
    found
}

/// The pools of the Debian (`/etc/php/X.Y/fpm/pool.d`), RHEL (`/etc/php-fpm.d`) and Remi
/// (`/etc/opt/remi/phpXY/php-fpm.d`) layouts.
pub fn pools(files: &dyn Files) -> Vec<Pool> {
    let mut pools = Vec::new();
    let mut add = |dir: &str, service: String, branch: Option<String>| {
        for text in configs(files, dir, ".conf") {
            for listen in listens(&text) {
                pools.push(Pool {
                    listen,
                    service: service.clone(),
                    branch: branch.clone(),
                });
            }
        }
    };
    for branch in files.list("/etc/php") {
        if branch.chars().all(|c| c.is_ascii_digit() || c == '.') && branch.contains('.') {
            add(
                &format!("/etc/php/{branch}/fpm/pool.d"),
                format!("php{branch}-fpm"),
                Some(branch.clone()),
            );
        }
    }
    add("/etc/php-fpm.d", "php-fpm".to_owned(), None);
    for scl in files.list("/etc/opt/remi") {
        let digits = scl.strip_prefix("php").unwrap_or("");
        if digits.len() >= 2 && digits.chars().all(|c| c.is_ascii_digit()) {
            add(
                &format!("/etc/opt/remi/{scl}/php-fpm.d"),
                format!("{scl}-php-fpm"),
                Some(format!("{}.{}", &digits[..1], &digits[1..])),
            );
        }
    }
    pools
}

/// The roots and the FastCGI targets of each nginx `server` block.
fn nginx(text: &str) -> Vec<Site> {
    let mut servers = Vec::new();
    let mut blocks: Vec<String> = Vec::new();
    let mut statement = String::new();
    let mut current: Option<Site> = None;
    for line in text.lines() {
        for c in line.split('#').next().unwrap_or("").chars().chain(['\n']) {
            match c {
                '{' => {
                    let name = statement.split_whitespace().next().unwrap_or("").to_owned();
                    if name == "server" && !blocks.iter().any(|b| b == "server") {
                        current = Some((Vec::new(), Vec::new()));
                    }
                    blocks.push(name);
                    statement.clear();
                }
                '}' => {
                    if blocks.pop().as_deref() == Some("server")
                        && !blocks.iter().any(|b| b == "server")
                    {
                        servers.extend(current.take());
                    }
                    statement.clear();
                }
                ';' => {
                    let mut words = statement.split_whitespace();
                    if let (Some(server), Some(directive), Some(value)) =
                        (current.as_mut(), words.next(), words.next())
                    {
                        match directive {
                            "root" => server.0.push(value.trim_matches('"').to_owned()),
                            "fastcgi_pass" => server.1.extend(Listen::parse(value)),
                            _ => {}
                        }
                    }
                    statement.clear();
                }
                _ => statement.push(c),
            }
        }
    }
    servers
}

/// The FastCGI target of an Apache handler or proxy (`proxy:unix:/run/php/x.sock|fcgi://localhost`,
/// `fcgi://127.0.0.1:9000/srv/app/$1`).
fn apache_target(value: &str) -> Option<Listen> {
    let value = value.trim_matches('"');
    if let Some(socket) = value.split("unix:").nth(1) {
        return Listen::parse(socket.split('|').next()?);
    }
    let address = value.split("fcgi://").nth(1)?.split('/').next()?;
    address.contains(':').then(|| Listen::parse(address))?
}

/// The document roots and FastCGI targets of an Apache configuration: outside any `<VirtualHost>` (the server's),
/// then of each virtual host.
fn apache(texts: &[String]) -> (Vec<String>, Vec<Listen>, Vec<Site>) {
    let (mut roots, mut targets, mut hosts) = (Vec::new(), Vec::new(), Vec::new());
    for text in texts {
        let mut host: Option<Site> = None;
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("<virtualhost") {
                host = Some((Vec::new(), Vec::new()));
                continue;
            }
            if lower.starts_with("</virtualhost") {
                hosts.extend(host.take());
                continue;
            }
            let mut words = line.split_whitespace();
            let (Some(directive), Some(value)) = (words.next(), words.last()) else {
                continue;
            };
            let (into_roots, into_targets) = match host.as_mut() {
                Some(h) => (&mut h.0, &mut h.1),
                None => (&mut roots, &mut targets),
            };
            match directive.to_ascii_lowercase().as_str() {
                "documentroot" => into_roots.push(value.trim_matches('"').to_owned()),
                "sethandler" | "proxypassmatch" | "proxypass" => {
                    into_targets.extend(apache_target(value))
                }
                _ => {}
            }
        }
    }
    (roots, targets, hosts)
}

/// Every document root whose PHP a known pool serves.
pub fn served(files: &dyn Files) -> Vec<Served> {
    let pools = pools(files);
    let mut sites: Vec<Site> = Vec::new();
    for dir in ["/etc/nginx/sites-enabled", "/etc/nginx/conf.d"] {
        let suffix = if dir.ends_with("conf.d") { ".conf" } else { "" };
        for text in configs(files, dir, suffix) {
            sites.extend(nginx(&text));
        }
    }
    let mut texts = configs(files, "/etc/apache2/sites-enabled", "");
    texts.extend(configs(files, "/etc/httpd/conf", ".conf"));
    texts.extend(configs(files, "/etc/httpd/conf.d", ".conf"));
    let (roots, targets, hosts) = apache(&texts);
    for (host_roots, host_targets) in hosts {
        let own_targets = !host_targets.is_empty();
        let host_roots = if host_roots.is_empty() {
            roots.clone()
        } else {
            host_roots
        };
        sites.push((
            host_roots,
            if own_targets {
                host_targets
            } else {
                targets.clone()
            },
        ));
    }
    sites.push((roots, targets));

    let mut served = Vec::new();
    for (site_roots, site_targets) in sites {
        for target in &site_targets {
            for pool in pools.iter().filter(|p| &p.listen == target) {
                for root in &site_roots {
                    let candidate = Served {
                        root: root.trim_end_matches('/').to_owned(),
                        pool: pool.clone(),
                    };
                    if !served.contains(&candidate) {
                        served.push(candidate);
                    }
                }
            }
        }
    }
    served
}

/// The runtime of a PHP application its web server passes to a pool: the version of that pool's `php-fpm` (from the
/// host runtimes, else its branch), and the service. None when no site serves it.
pub fn runtime_for(path: &str, served: &[Served], host_runtimes: &[Value]) -> Option<Value> {
    let path = path.trim_end_matches('/');
    let site = served
        .iter()
        .filter(|s| s.root == path || s.root.starts_with(&format!("{path}/")))
        .min_by_key(|s| s.root.len())?;
    let pool = &site.pool;
    let binary = host_runtimes.iter().find(|r| {
        r["name"] == "php-fpm"
            && match &pool.branch {
                Some(branch) => r["service"] == format!("php{branch}-fpm"),
                None => r.get("service").is_none(),
            }
    });
    let version = binary
        .and_then(|r| r["version"].as_str())
        .map(str::to_owned)
        .or_else(|| pool.branch.clone())?;
    Some(json!({"name": "php", "version": version, "service": pool.service}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::files::{Memory, Root};

    fn fixture(name: &str) -> Root {
        Root(format!("{}/tests/fixtures/fpm/{name}", env!("CARGO_MANIFEST_DIR")).into())
    }

    #[test]
    fn reads_the_debian_pools_and_the_nginx_sites() {
        let root = fixture("debian");
        let socket = Listen::Socket("/run/php/php8.2-fpm.sock".into());
        assert_eq!(
            pools(&root),
            vec![Pool {
                listen: socket.clone(),
                service: "php8.2-fpm".into(),
                branch: Some("8.2".into())
            }]
        );
        assert_eq!(
            served(&root),
            vec![Served {
                root: "/srv/shop/public".into(),
                pool: pools(&root)[0].clone()
            }],
            "The default site passes nothing to PHP (commented); the shop site, through a link outside the root's own paths."
        );
        let runtimes = [
            json!({"name": "php", "version": "8.2.28", "path": "/usr/bin/php8.2"}),
            json!({"name": "php-fpm", "version": "8.2.28", "path": "/usr/sbin/php-fpm8.2", "service": "php8.2-fpm"}),
        ];
        let served = served(&root);
        assert_eq!(
            runtime_for("/srv/shop", &served, &runtimes),
            Some(json!({"name": "php", "version": "8.2.28", "service": "php8.2-fpm"}))
        );
        assert_eq!(
            runtime_for("/srv/shop/public/", &served, &runtimes),
            Some(json!({"name": "php", "version": "8.2.28", "service": "php8.2-fpm"}))
        );
        assert_eq!(
            runtime_for("/srv/shop", &served, &[]),
            Some(json!({"name": "php", "version": "8.2", "service": "php8.2-fpm"})),
            "Its branch when the binary was not found."
        );
        assert_eq!(runtime_for("/srv/sho", &served, &runtimes), None);
        assert_eq!(runtime_for("/srv/other", &served, &runtimes), None);
    }

    #[test]
    fn reads_the_rhel_pools_and_the_apache_handler() {
        let root = fixture("rocky");
        let served = served(&root);
        assert_eq!(
            served,
            vec![Served {
                root: "/var/www/html".into(),
                pool: Pool {
                    listen: Listen::Socket("/run/php-fpm/www.sock".into()),
                    service: "php-fpm".into(),
                    branch: None
                }
            }],
            "The handler of php.conf, on the server's document root."
        );
        let runtimes = [
            json!({"name": "php-fpm", "version": "8.0.30", "path": "/usr/sbin/php-fpm"}),
            json!({"name": "php-fpm", "version": "8.3.1", "path": "/usr/sbin/php-fpm8.3", "service": "php8.3-fpm"}),
        ];
        assert_eq!(
            runtime_for("/var/www/html", &served, &runtimes),
            Some(json!({"name": "php", "version": "8.0.30", "service": "php-fpm"}))
        );
        assert_eq!(
            runtime_for("/var/www/html", &served, &[]),
            None,
            "No version known."
        );
    }

    #[test]
    fn reads_remi_pools_tcp_listens_and_virtual_hosts() {
        let mut files = Memory::default();
        let mut put = |path: &str, text: &str| {
            files.0.insert(path.into(), text.as_bytes().to_vec());
        };
        put(
            "/etc/opt/remi/php83/php-fpm.d/www.conf",
            "[www]\nlisten = 127.0.0.1:9083 ; tcp\n[api]\nlisten = /run/$pool.sock\n",
        );
        put("/etc/opt/remi/php83/php-fpm.d/README", "listen = 1");
        put("/etc/opt/remi/php/php-fpm.d/x.conf", "[x]\nlisten = 9000\n");
        put("/etc/php/latest/fpm/pool.d/x.conf", "[x]\nlisten = 9001\n");
        put(
            "/etc/httpd/conf.d/sites.conf",
            "DocumentRoot \"/var/www/html\"\n<VirtualHost *:80>\n  DocumentRoot /srv/api/public\n  ProxyPassMatch ^/(.*\\.php)$ fcgi://127.0.0.1:9083/srv/api/public/$1\n</VirtualHost>\n<VirtualHost *:80>\n  DocumentRoot /srv/blog\n  SetHandler \"proxy:unix:/run/api.sock|fcgi://localhost\"\n</VirtualHost>\n<VirtualHost *:80>\n  # SetHandler \"proxy:unix:/run/api.sock|fcgi://localhost\"\n  DocumentRoot /srv/static\n</VirtualHost>\n",
        );
        put(
            "/etc/nginx/conf.d/admin.conf",
            "server {\n  root /srv/admin; # comment\n  location ~ \\.php$ { fastcgi_pass [::1]:9083; }\n}\nserver { root /srv/none; fastcgi_pass backend; }\n",
        );
        put(
            "/etc/nginx/conf.d/skip.txt",
            "server { root /srv/skip; fastcgi_pass 127.0.0.1:9083; }",
        );

        let www = Pool {
            listen: Listen::Port(9083),
            service: "php83-php-fpm".into(),
            branch: Some("8.3".into()),
        };
        let api = Pool {
            listen: Listen::Socket("/run/api.sock".into()),
            ..www.clone()
        };
        assert_eq!(
            pools(&files),
            vec![www.clone(), api.clone()],
            "Only `phpXY`, only `X.Y`, only `.conf`."
        );
        let served = served(&files);
        let roots: Vec<(&str, &Listen)> = served
            .iter()
            .map(|s| (s.root.as_str(), &s.pool.listen))
            .collect();
        assert_eq!(
            roots,
            vec![
                ("/srv/admin", &www.listen),
                ("/srv/api/public", &www.listen),
                ("/srv/blog", &api.listen),
            ]
        );
        assert_eq!(
            runtime_for("/srv/api", &served, &[]),
            Some(json!({"name": "php", "version": "8.3", "service": "php83-php-fpm"}))
        );
        assert_eq!(
            runtime_for("/srv/static", &served, &[]),
            None,
            "A commented handler."
        );
        assert_eq!(runtime_for("/var/www/html", &served, &[]), None);
    }

    #[test]
    fn parses_listen_values() {
        assert_eq!(
            Listen::parse("\"/run/a.sock\""),
            Some(Listen::Socket("/run/a.sock".into()))
        );
        assert_eq!(
            Listen::parse("unix:/run/a.sock"),
            Some(Listen::Socket("/run/a.sock".into()))
        );
        assert_eq!(Listen::parse("9000"), Some(Listen::Port(9000)));
        assert_eq!(Listen::parse("[::1]:9001"), Some(Listen::Port(9001)));
        assert_eq!(Listen::parse("backend"), None);
        assert_eq!(apache_target("fcgi://localhost/"), None, "No port.");
    }
}
