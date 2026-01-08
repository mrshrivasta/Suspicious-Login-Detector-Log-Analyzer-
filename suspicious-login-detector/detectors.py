import pandas as pd
from typing import Dict, List, Any
import config


class SuspiciousLoginDetector:
    def __init__(self, df: pd.DataFrame):
        self.df = df.copy()
        self.alerts: List[Dict[str, Any]] = []

        if 'timestamp_parsed' in self.df.columns:
            self.df['timestamp_parsed'] = pd.to_datetime(
                self.df['timestamp_parsed'],
                errors='coerce'
            )

    def detect_brute_force(self) -> List[Dict[str, Any]]:
        login_attempts = self.df[
            self.df['path'].astype(str).str.contains(
                '|'.join(config.Config.LOGIN_PATHS),
                case=False,
                na=False
            )
        ]

        failed_logins = login_attempts[login_attempts['status'] >= 400]

        if failed_logins.empty:
            return []

        ip_stats = failed_logins.groupby('ip').agg(
            count=('status', 'count'),
            first_seen=('timestamp_parsed', 'min'),
            last_seen=('timestamp_parsed', 'max')
        )

        brute_force_ips = ip_stats[
            ip_stats['count'] >= config.Config.THRESHOLDS['failed_logins_per_ip']
        ]

        alerts = []
        for ip, stats in brute_force_ips.iterrows():
            alerts.append({
                'type': 'BRUTE_FORCE',
                'ip': ip,
                'attempts': int(stats['count']),
                'duration': (
                    (stats['last_seen'] - stats['first_seen']).total_seconds() / 60
                    if pd.notna(stats['first_seen']) and pd.notna(stats['last_seen'])
                    else 0
                ),
                'severity': 'HIGH' if stats['count'] > 20 else 'MEDIUM'
            })

        return alerts

    def detect_rate_limits(self) -> List[Dict[str, Any]]:
        if 'timestamp_parsed' not in self.df.columns:
            return []

        df_1min = (
            self.df
            .set_index('timestamp_parsed')
            .resample('1min')
            .size()
            .reset_index(name='requests')
        )

        ip_requests = (
            self.df
            .dropna(subset=['timestamp_parsed'])
            .groupby([
                'ip',
                pd.Grouper(key='timestamp_parsed', freq='1min')
            ])
            .size()
            .reset_index(name='count')
        )

        high_rate_ips = ip_requests[
            ip_requests['count'] > config.Config.THRESHOLDS['requests_per_minute']
        ]

        alerts = []
        for _, row in high_rate_ips.iterrows():
            alerts.append({
                'type': 'RATE_LIMIT_EXCEEDED',
                'ip': row['ip'],
                'requests_per_minute': int(row['count']),
                'timestamp': row['timestamp_parsed'],
                'severity': 'HIGH'
            })

        return alerts

    def detect_suspicious_user_agents(self) -> List[Dict[str, Any]]:
        ua_lower = self.df['user_agent'].astype(str).str.lower()

        matches = []
        for pattern in config.Config.SUSPICIOUS_UA_PATTERNS:
            m = ua_lower[ua_lower.str.contains(pattern, regex=True)]
            if not m.empty:
                matches.append(m)

        if not matches:
            return []

        suspicious_df = pd.concat(matches, ignore_index=True)
        ua_counts = suspicious_df.value_counts()

        alerts = []
        for ua, count in ua_counts.items():
            if count >= config.Config.THRESHOLDS['suspicious_user_agents']:
                alerts.append({
                    'type': 'SUSPICIOUS_UA',
                    'user_agent': ua,
                    'occurrences': int(count),
                    'severity': 'MEDIUM'
                })

        return alerts

    def detect_geo_anomalies(self) -> List[Dict[str, Any]]:
        try:
            import geoip2.database
            reader = geoip2.database.Reader(config.Config.GEO_DB_PATH)
        except Exception:
            return []

        countries = self.df['ip'].astype(str).apply(
            lambda ip: self._get_country(reader, ip)
        )

        country_counts = countries.value_counts()

        alerts = []
        if len(country_counts) > 10:
            alerts.append({
                'type': 'GEO_DIVERSITY_HIGH',
                'unique_countries': int(len(country_counts)),
                'top_countries': country_counts.head().to_dict(),
                'severity': 'LOW'
            })

        reader.close()
        return alerts

    def _get_country(self, reader, ip: str) -> str:
        try:
            response = reader.country(ip)
            return response.country.iso_code or 'UNKNOWN'
        except Exception:
            return 'UNKNOWN'

    def run_all_detections(self) -> List[Dict[str, Any]]:
        self.alerts = []
        self.alerts.extend(self.detect_brute_force())
        self.alerts.extend(self.detect_rate_limits())
        self.alerts.extend(self.detect_suspicious_user_agents())
        self.alerts.extend(self.detect_geo_anomalies())
        return self.alerts
