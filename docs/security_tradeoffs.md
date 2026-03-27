# Security Trade-offs

Documentation for SentinelAuth by **ANISH KUMAR**.

- JWT access tokens remain stateless for scale, but revocation requires a distributed store lookup for every request.
- Rich authorization claims reduce policy round-trips, but increase token sensitivity and require shorter TTLs.
- Refresh token rotation improves replay resistance, but adds operational complexity around token family tracking.
- Service-to-service JWTs avoid static network trust, but secret rotation and audience management must be operationalized.
- The local project ships demo bootstrap users for developer onboarding; production deployments must replace them with a real identity source and managed secrets.
