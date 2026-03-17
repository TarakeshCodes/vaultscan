import random
import math
from datetime import datetime

class AIAnalyzer:
    def __init__(self):
        self.severity_weights = {
            "Critical": 10.0,
            "High": 7.5,
            "Medium": 4.0,
            "Low": 1.5,
            "Info": 0.2
        }
        self.owasp_risk_map = {
            "A01:2021 - Broken Access Control": 0.9,
            "A02:2021 - Cryptographic Failures": 0.8,
            "A03:2021 - Injection": 1.0,
            "A04:2021 - Insecure Design": 0.6,
            "A05:2021 - Security Misconfiguration": 0.7,
            "A06:2021 - Vulnerable and Outdated Components": 0.75,
            "A07:2021 - Identification and Authentication Failures": 0.85,
            "A08:2021 - Software and Data Integrity Failures": 0.8,
            "A09:2021 - Security Logging and Monitoring Failures": 0.5,
            "A10:2021 - Server-Side Request Forgery": 0.9,
        }

    def analyze(self, vulnerabilities, target_url):
        risk_score = self._calculate_risk_score(vulnerabilities)
        severity_dist = self._severity_distribution(vulnerabilities)
        prioritized = self._prioritize_threats(vulnerabilities)
        summaries = self._generate_summaries(vulnerabilities)
        fixes = self._generate_fixes(vulnerabilities)
        insights = self._generate_insights(vulnerabilities, target_url, risk_score)
        threat_map = self._generate_threat_map(vulnerabilities)

        return {
            "risk_score": risk_score,
            "risk_level": self._risk_level(risk_score),
            "risk_label": self._risk_label(risk_score),
            "severity_distribution": severity_dist,
            "prioritized_threats": prioritized,
            "vulnerability_summaries": summaries,
            "fix_suggestions": fixes,
            "security_insights": insights,
            "threat_heatmap": threat_map,
            "executive_summary": self._executive_summary(vulnerabilities, risk_score, target_url),
            "generated_at": datetime.now().isoformat(),
            "scan_grade": self._calculate_grade(risk_score)
        }

    def _calculate_risk_score(self, vulns):
        if not vulns:
            return 5.0
        total_weight = 0
        max_possible = 100
        for v in vulns:
            weight = self.severity_weights.get(v['severity'], 1.0)
            owasp_mult = self.owasp_risk_map.get(v.get('owasp_category', ''), 0.7)
            cvss = v.get('cvss', 5.0)
            total_weight += weight * owasp_mult * (cvss / 10.0) * 2.5
        raw_score = min(total_weight, max_possible)
        normalized = (1 - math.exp(-raw_score / 30)) * 100
        return round(normalized, 1)

    def _risk_level(self, score):
        if score >= 80: return "Critical"
        if score >= 60: return "High"
        if score >= 40: return "Medium"
        if score >= 20: return "Low"
        return "Minimal"

    def _risk_label(self, score):
        if score >= 80: return "CRITICAL RISK"
        if score >= 60: return "HIGH RISK"
        if score >= 40: return "MODERATE RISK"
        if score >= 20: return "LOW RISK"
        return "MINIMAL RISK"

    def _calculate_grade(self, score):
        if score >= 80: return "F"
        if score >= 65: return "D"
        if score >= 50: return "C"
        if score >= 35: return "B"
        if score >= 20: return "B+"
        return "A"

    def _severity_distribution(self, vulns):
        dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for v in vulns:
            dist[v['severity']] = dist.get(v['severity'], 0) + 1
        return dist

    def _prioritize_threats(self, vulns):
        def priority_score(v):
            sev_score = self.severity_weights.get(v['severity'], 1.0)
            owasp_score = self.owasp_risk_map.get(v.get('owasp_category', ''), 0.5)
            cvss = v.get('cvss', 5.0)
            return sev_score * owasp_score * cvss

        sorted_vulns = sorted(vulns, key=priority_score, reverse=True)
        result = []
        for i, v in enumerate(sorted_vulns[:10]):
            result.append({
                **v,
                "priority_rank": i + 1,
                "priority_score": round(priority_score(v), 2),
                "exploit_likelihood": self._exploit_likelihood(v),
                "business_impact": self._business_impact(v)
            })
        return result

    def _exploit_likelihood(self, vuln):
        high_exploit = ["SQL Injection", "Command Injection", "XSS", "SSRF", "Default Credentials"]
        if any(h in vuln['name'] for h in high_exploit):
            return "High"
        if vuln['severity'] in ['Critical', 'High']:
            return "Medium-High"
        return "Medium"

    def _business_impact(self, vuln):
        critical_impact = ["SQL Injection", "Command Injection", "Default Credentials", "XXE", "SSRF", "Deserialization"]
        if any(c in vuln['name'] for c in critical_impact):
            return "Data breach, full system compromise"
        if vuln['severity'] == 'High':
            return "Significant data exposure or service disruption"
        if vuln['severity'] == 'Medium':
            return "Partial data access or user impact"
        return "Minor information disclosure"

    def _generate_summaries(self, vulns):
        summaries = {}
        templates = {
            "SQL Injection": "SQL injection vulnerabilities allow attackers to manipulate backend database queries by injecting malicious SQL code through user-controlled inputs. This can lead to unauthorized data access, data manipulation, authentication bypass, and in some cases full database server compromise.",
            "XSS": "Cross-site scripting vulnerabilities enable attackers to inject malicious client-side scripts into web pages viewed by other users. These scripts execute in the victim's browser context and can steal session tokens, capture keystrokes, redirect users, or perform actions on their behalf.",
            "Command Injection": "Command injection allows attackers to execute arbitrary operating system commands on the host server. This represents one of the most severe vulnerability classes, potentially enabling complete system takeover, data exfiltration, and lateral movement within the network.",
            "CSRF": "Cross-site request forgery vulnerabilities allow attackers to trick authenticated users into unknowingly submitting malicious requests. Without CSRF tokens, any website can forge requests to your application using the victim's active session.",
            "CORS": "CORS misconfiguration allows unauthorized cross-origin access to your API resources. Attackers can create malicious websites that make cross-origin requests to your application, potentially stealing sensitive data from authenticated users.",
            "default": "This vulnerability represents a significant security risk that could be exploited by attackers to compromise the confidentiality, integrity, or availability of the application and its data."
        }
        for v in vulns:
            key = next((k for k in templates if k.lower() in v['name'].lower()), 'default')
            summaries[v['id']] = {
                "vuln_id": v['id'],
                "natural_language": templates[key],
                "attack_scenario": self._attack_scenario(v),
                "impact_analysis": self._impact_analysis(v)
            }
        return summaries

    def _attack_scenario(self, vuln):
        scenarios = {
            "SQL Injection": "An attacker discovers the vulnerable parameter through automated scanning. They craft a SQL payload that bypasses authentication (e.g., ' OR 1=1--) or extracts sensitive data using UNION-based injection. Within minutes, the attacker can dump the entire database.",
            "XSS": "An attacker crafts a malicious URL containing an XSS payload and shares it via email or social media. When a victim clicks the link, the script executes in their browser, silently exfiltrating their session cookie to an attacker-controlled server. The attacker then uses this cookie to hijack the victim's session.",
            "SSRF": "An attacker discovers a parameter that accepts URLs and tests it with internal network addresses. They successfully reach the cloud metadata service (169.254.169.254) and extract IAM credentials, gaining access to cloud resources.",
            "default": "An attacker identifies the vulnerability through manual testing or automated tools. They exploit it to gain unauthorized access to sensitive functionality or data, potentially escalating privileges or pivoting to other systems."
        }
        key = next((k for k in scenarios if k.lower() in vuln['name'].lower()), 'default')
        return scenarios[key]

    def _impact_analysis(self, vuln):
        if vuln['severity'] == 'Critical':
            return "Complete system compromise is possible. Immediate remediation is required. Data breach notification may be legally required under GDPR/CCPA."
        elif vuln['severity'] == 'High':
            return "Significant data exposure or unauthorized access is possible. Remediation should be prioritized within 24-48 hours."
        elif vuln['severity'] == 'Medium':
            return "Moderate security risk that could be exploited under specific conditions. Address within the next sprint or release cycle."
        else:
            return "Low-risk finding that represents a hardening opportunity. Address during scheduled maintenance."

    def _generate_fixes(self, vulns):
        fix_db = {
            "SQL Injection": {
                "title": "Prevent SQL Injection",
                "steps": [
                    "Use parameterized queries (prepared statements) for ALL database interactions",
                    "Implement an ORM (SQLAlchemy, Hibernate, Sequelize) to abstract raw SQL",
                    "Apply input validation with allowlists for expected data formats",
                    "Use stored procedures with proper parameter binding",
                    "Deploy a Web Application Firewall (WAF) as a defense-in-depth measure",
                    "Enable least-privilege database accounts — app users should not have DROP privileges",
                    "Implement error handling that does not expose database error messages to users"
                ],
                "code_example": "# ✅ Safe - Parameterized Query\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n\n# ❌ Unsafe - String Concatenation\ncursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
                "references": ["OWASP SQL Injection Prevention Cheat Sheet", "CWE-89"]
            },
            "XSS": {
                "title": "Prevent Cross-Site Scripting",
                "steps": [
                    "Encode all user-supplied data before rendering in HTML (use context-aware encoding)",
                    "Implement a strict Content-Security-Policy (CSP) header",
                    "Use modern frameworks with built-in XSS protection (React, Angular, Vue)",
                    "Validate and sanitize all inputs on the server side",
                    "Use HTTPOnly and Secure flags on session cookies",
                    "Avoid using innerHTML, document.write, or eval() with user data",
                    "Implement DOMPurify for any necessary HTML sanitization"
                ],
                "code_example": "// ✅ Safe - React auto-escapes\n<div>{userInput}</div>\n\n// ❌ Unsafe - Raw HTML injection\n<div dangerouslySetInnerHTML={{__html: userInput}} />",
                "references": ["OWASP XSS Prevention Cheat Sheet", "CWE-79"]
            },
            "CSRF": {
                "title": "Implement CSRF Protection",
                "steps": [
                    "Generate cryptographically random CSRF tokens for each user session",
                    "Include CSRF token in all state-changing forms as a hidden field",
                    "Validate CSRF token on server side for every POST/PUT/DELETE request",
                    "Use SameSite=Strict or SameSite=Lax cookie attribute",
                    "Verify Origin and Referer headers as secondary defense",
                    "Use the Synchronizer Token Pattern or Double Submit Cookie pattern"
                ],
                "code_example": "# Flask-WTF example\nfrom flask_wtf.csrf import CSRFProtect\napp = Flask(__name__)\ncsrf = CSRFProtect(app)\n\n# In template\n<form method='POST'>\n  {{ form.csrf_token }}\n  ...\n</form>",
                "references": ["OWASP CSRF Prevention Cheat Sheet", "CWE-352"]
            },
            "default": {
                "title": "Security Hardening Recommendation",
                "steps": [
                    "Apply the principle of least privilege to all components",
                    "Implement proper input validation and output encoding",
                    "Keep all dependencies updated to latest secure versions",
                    "Enable security logging and monitoring for anomaly detection",
                    "Conduct regular security code reviews and penetration testing",
                    "Follow OWASP Secure Coding Practices guidelines"
                ],
                "code_example": "# Always validate and sanitize inputs\ndef process_input(user_data):\n    if not isinstance(user_data, str):\n        raise ValueError('Invalid input type')\n    sanitized = html.escape(user_data.strip())\n    return sanitized[:500]  # Length limit",
                "references": ["OWASP Top 10", "NIST Cybersecurity Framework"]
            }
        }
        fixes = {}
        for v in vulns:
            key = next((k for k in fix_db if k.lower() in v['name'].lower()), 'default')
            fixes[v['id']] = {
                "vuln_id": v['id'],
                "vuln_name": v['name'],
                "severity": v['severity'],
                **fix_db[key],
                "estimated_effort": self._estimate_effort(v),
                "priority": "Immediate" if v['severity'] in ['Critical', 'High'] else "Planned"
            }
        return fixes

    def _estimate_effort(self, vuln):
        effort_map = {
            "Critical": "1-2 days (urgent)",
            "High": "2-5 days",
            "Medium": "1-2 weeks",
            "Low": "Next sprint",
            "Info": "Backlog"
        }
        return effort_map.get(vuln['severity'], "1-2 weeks")

    def _generate_insights(self, vulns, target_url, risk_score):
        insights = []
        sev_dist = self._severity_distribution(vulns)
        critical_count = sev_dist.get('Critical', 0)
        high_count = sev_dist.get('High', 0)

        if critical_count > 0:
            insights.append({
                "type": "critical_alert",
                "title": "Immediate Action Required",
                "message": f"Found {critical_count} critical vulnerabilities requiring immediate remediation. These pose an imminent risk of data breach.",
                "icon": "🚨"
            })

        injection_vulns = [v for v in vulns if 'injection' in v['name'].lower()]
        if injection_vulns:
            insights.append({
                "type": "injection_risk",
                "title": "Injection Attack Surface",
                "message": f"Multiple injection vulnerabilities ({len(injection_vulns)}) detected. Implement parameterized queries and input validation framework-wide.",
                "icon": "💉"
            })

        auth_vulns = [v for v in vulns if 'auth' in v['owasp_category'].lower() or 'credentials' in v['name'].lower()]
        if auth_vulns:
            insights.append({
                "type": "auth_weakness",
                "title": "Authentication Weaknesses",
                "message": f"{len(auth_vulns)} authentication-related vulnerabilities found. Consider implementing MFA and reviewing your session management.",
                "icon": "🔑"
            })

        config_vulns = [v for v in vulns if 'misconfiguration' in v['owasp_category'].lower() or 'header' in v['name'].lower()]
        if len(config_vulns) > 3:
            insights.append({
                "type": "hardening",
                "title": "Security Hardening Needed",
                "message": f"{len(config_vulns)} security hardening issues found. Many of these can be fixed with a single security headers middleware.",
                "icon": "🛡️"
            })

        insights.append({
            "type": "recommendation",
            "title": "Next Steps",
            "message": "Implement a Security Development Lifecycle (SDL): add SAST/DAST to CI/CD pipelines, conduct quarterly penetration tests, and train developers on secure coding.",
            "icon": "📋"
        })

        return insights

    def _generate_threat_map(self, vulns):
        categories = {}
        for v in vulns:
            cat = v.get('owasp_category', 'Unknown')
            short_cat = cat.split(' - ')[-1] if ' - ' in cat else cat
            if short_cat not in categories:
                categories[short_cat] = {"name": short_cat, "count": 0, "max_severity": "Info", "score": 0}
            categories[short_cat]['count'] += 1
            sev_order = ['Info', 'Low', 'Medium', 'High', 'Critical']
            if sev_order.index(v['severity']) > sev_order.index(categories[short_cat]['max_severity']):
                categories[short_cat]['max_severity'] = v['severity']
            categories[short_cat]['score'] += self.severity_weights.get(v['severity'], 1.0)

        return sorted(list(categories.values()), key=lambda x: x['score'], reverse=True)

    def _executive_summary(self, vulns, risk_score, target_url):
        sev_dist = self._severity_distribution(vulns)
        total = len(vulns)
        critical = sev_dist.get('Critical', 0)
        high = sev_dist.get('High', 0)
        risk_level = self._risk_level(risk_score)
        grade = self._calculate_grade(risk_score)

        return {
            "target": target_url,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "grade": grade,
            "total_vulnerabilities": total,
            "critical_count": critical,
            "high_count": high,
            "narrative": f"VaultScan AI completed a comprehensive security assessment of {target_url}. "
                        f"The overall security posture is rated {risk_level} with a risk score of {risk_score}/100 "
                        f"(Grade: {grade}). {total} vulnerabilities were identified, including {critical} critical "
                        f"and {high} high-severity findings. "
                        f"{'Immediate remediation is strongly recommended.' if risk_score >= 60 else 'Scheduled remediation is advised for the identified findings.'}"
        }
