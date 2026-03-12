# Technology Stack
> Auto-generated from config.yaml on 2026-03-12 21:20:54

---

## Backend

| Field | Value |
|-------|-------|
| Language / Runtime |  |
| Framework |  |
| Web Server |  |
| Version |  |

## Frontend

| Field | Value |
|-------|-------|
| Framework |  |
| Template Engine |  |
| CSS Framework |  |
| Build Tool |  |

## Database

| Field | Value |
|-------|-------|
| Type |  |
| ORM |  |
| Version |  |

## Authentication

| Field | Value |
|-------|-------|
| Session Type |  |
| Token Algorithm |  |
| MFA Present | No |
| OAuth Provider |  |
| SSO Type |  |

## Infrastructure

| Field | Value |
|-------|-------|
| Cloud Provider |  |
| Container Platform |  |
| CDN |  |
| WAF |  |

## File Upload

| Field | Value |
|-------|-------|
| Allowed | No |
| Storage Type |  |
| CDN Served | No |
| Direct Execution | No |
| MIME Validation |  |

## API

| Field | Value |
|-------|-------|
| Style | REST |
| Version |  |
| Documentation |  |
| Auth Method | bearer |

---

## Module Selection Guide

Based on the tech stack above, prioritize these exploitation modules:

| Tech Stack Indicator | Recommended Modules |
|----------------------|---------------------|
| SQL Database | SQL_INJECTION |
| Template Engine | SSTI |
| JWT Auth | JWT_SECURITY |
| File Upload | FILE_UPLOAD, PATH_TRAVERSAL |
| GraphQL API | GRAPHQL, MASS_ASSIGNMENT |
| OAuth/SSO | OAUTH |
| Any Web App | XSS, CSRF, IDOR, AUTHENTICATION, AUTHORIZATION |
