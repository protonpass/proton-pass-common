use std::collections::HashMap;

// Include the domains file and images directory at compile time
static ISSUER_FILE: &str = include_str!("../resources/issuerInfos.txt");
static OVERRIDE_FILE: &str = include_str!("../resources/issuerManualOverrides.txt");

#[derive(Clone)]
pub struct IssuerInfo {
    pub domain: String,
    pub icon_url: String,
}

pub struct TOTPIssuerMapper {
    issuer_infos: HashMap<String, IssuerInfo>,
}

impl Default for TOTPIssuerMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl TOTPIssuerMapper {
    pub fn new() -> Self {
        let mut domains = Vec::new();
        let infos = Self::load_domains(ISSUER_FILE);
        let overrides = Self::load_domains(OVERRIDE_FILE);
        domains.extend(infos);
        domains.extend(overrides);
        let issuer_infos = Self::get_issuer_info(&domains);

        TOTPIssuerMapper { issuer_infos }
    }

    pub fn lookup(&self, issuer: &str) -> Option<IssuerInfo> {
        // Normalize the issuer string
        let normalized = issuer.to_lowercase();

        self.issuer_infos.get(&normalized).cloned()
    }

    fn load_domains(file: &str) -> Vec<String> {
        file.lines()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }

    fn get_issuer_info(infos: &[String]) -> HashMap<String, IssuerInfo> {
        let mut map = HashMap::new();

        for info in infos {
            // Extract parts before TLD
            let components: Vec<&str> = info.split(';').collect();
            if components.is_empty() || components.len() != 3 {
                continue;
            }

            let main_name = components[0].to_lowercase();
            let domain = components[1].to_string();
            let icon_url = components[2].to_string();

            map.insert(
                main_name.clone(),
                IssuerInfo {
                    domain: domain.to_string(),
                    icon_url,
                },
            );
        }

        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_domains() {
        let domains = TOTPIssuerMapper::load_domains(ISSUER_FILE);
        assert!(!domains.is_empty());
    }

    #[test]
    fn test_info_check() {
        let mapper = TOTPIssuerMapper::new();
        let infos = mapper.lookup("protonMail");
        assert!(!infos.clone().unwrap().domain.is_empty());
        assert!(infos.clone().unwrap().icon_url == "https://proton.me/favicons/apple-touch-icon.png");

        let aws_infos = mapper.lookup("aws.amazon");
        assert!(!aws_infos.clone().unwrap().domain.is_empty());
        assert!(aws_infos.clone().unwrap().icon_url == "https://t0.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://aws.amazon.com&size=256");
    }
    #[test]
    fn test_bad_domain_check() {
        let mapper = TOTPIssuerMapper::new();
        let infos = mapper.lookup("non existing domain");
        assert!(infos.is_none());
    }
}
