# Understanding Software Artifacts

## 🧩 What Are Artifacts?

In software development, **artifacts** refer to any byproduct or tangible item produced during the development lifecycle. These are generated as part of planning, coding, building, testing, and deploying a software project.

Artifacts can be categorized into two major types:

- **Source Artifacts**: Files created directly by developers, such as source code, documentation, diagrams, and configuration files.
- **Derived Artifacts**: Files produced by tools and processes—like compiled binaries, Docker images, logs, test reports, and SBOM files.

---

## 🧰 Common Examples

| Type                | Example                          | Description                                           |
|---------------------|----------------------------------|-------------------------------------------------------|
| Source              | `.js`, `.go`, `.py` files        | Core source code of the application                  |
| Build               | `.exe`, `.jar`, `.wasm`          | Compiled application ready for deployment            |
| Documentation       | `README.md`, architecture docs   | Internal or external documentation                   |
| Dependency          | `package-lock.json`, `go.sum`    | Captures dependency versions and relationships       |
| Configuration       | `docker-compose.yml`, `.env`     | Manages environment and infrastructure setup         |
| Testing             | Coverage reports, test logs      | Evidence of system validity and quality assurance    |
| Vulnerability       | SBOMs, scan results (e.g. Diggity)| Security metadata for auditing and compliance        |

---

## 💡 Why Artifacts Matter

Artifacts provide **visibility, traceability, and accountability** throughout the software lifecycle. Understanding them helps teams:

- 🔍 **Track and audit** progress and decisions (e.g. why a certain library was used)
- 🛡️ **Ensure security and compliance** (especially with SBOMs and vulnerability data)
- 🛠️ **Facilitate debugging and troubleshooting** via logs and reports
- 🔄 **Enable reproducibility** of builds and deployments
- 🧑‍🏫 **Mentor and onboard** others by offering transparent insights into project structure

---

## 🚀 Final Thoughts

Recognizing and categorizing software artifacts isn’t just bookkeeping—it’s foundational to creating scalable, secure, and maintainable systems. Whether you're building from scratch or improving an existing pipeline, artifacts are the blueprint, the evidence, and the fingerprint of your engineering work.
