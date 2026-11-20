# Model

## Algorithm

A `RandomForestClassifier` (scikit-learn, `n_estimators=100`,
`random_state=42`) trained at runtime from `data/training_urls.csv`
(~100 labeled example URLs: well-known legitimate domains and realistic
phishing patterns).

## Features (URL lexical only)

`url_length`, `host_length`, `dot_count`, `hyphen_count`, `digit_count`,
`digit_ratio`, `has_at`, `has_ip`, `is_punycode`, `subdomain_count`,
`path_length`, `query_length`, `suspicious_tld`, `entropy`, `has_https`,
`slash_count`, `host_digit_count`, `double_slash_in_path`,
`longest_label`.

Using URL features only means the model can score a URL even when the
page cannot be fetched.

## How the score is built

```
score = min(100, round(ml_probability * 100 * 0.6 + rule_points))
```

`rule_points` (capped at 45) come from the rule signals:

| Signal | Points |
| --- | --- |
| IP-literal host | 25 |
| Brand impersonation | 25 |
| `@` in the URL | 15 |
| Punycode domain (xn--) | 15 |
| Suspicious TLD | 10 |
| 4+ subdomains | 10 |
| Password form on the page | 10 |
| Hidden iframe(s) on the page | 10 |
| Very long URL / many digits | 5 |
| Most resources from other domains | 5 |
| Favicon from another domain | 5 |

## Verdict bands

| Score | Label |
| --- | --- |
| 70-100 | PHISHING |
| 40-69 | SUSPICIOUS |
| 0-39 | LEGIT |

## Limits

- The training set is small and synthetic: the model recognizes
  patterns like the examples, not every phishing trick in the wild.
- A legitimate site on an unusual domain can score SUSPICIOUS.
- A clean-looking phishing page with no fetched HTML scores lower
  than the same page with its HTML analyzed.
- Treat every verdict as a hint, not proof.
