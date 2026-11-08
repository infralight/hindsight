# The fork's Hindsight API with the RBAC extension (SSO, API tokens, bank sharing) in it.
#
# Unlike the other extensions here, the base cannot be an upstream release: the fork
# also patches the server (audit actor, audit-log read for the validator, fail-closed
# MCP tool filtering). Build the API image from this checkout first, then this on top.
# From the repository root:
#   docker build -f docker/standalone/Dockerfile --target api-only -t hindsight-api-fork .
#   docker build -f hindsight-extensions/rbac/Dockerfile \
#     --build-arg HINDSIGHT_IMAGE=hindsight-api-fork -t hindsight-api-rbac .
#
# Run with the three RBAC slots enabled:
#   HINDSIGHT_API_TENANT_EXTENSION=hindsight_ext_rbac:RbacTenantExtension
#   HINDSIGHT_API_OPERATION_VALIDATOR_EXTENSION=hindsight_ext_rbac:RbacOperationValidator
#   HINDSIGHT_API_HTTP_EXTENSION=hindsight_ext_rbac:RbacHttpExtension
#   HINDSIGHT_API_EXTENSION_PASSTHROUGH_HEADERS=user-agent,x-forwarded-for
# plus HINDSIGHT_API_TENANT_AUTH_MODE (optional | required) and the OIDC settings
# (see README.md).
ARG HINDSIGHT_IMAGE
FROM ${HINDSIGHT_IMAGE}

# Everything the extension imports (PyJWT, aiohttp, asyncpg, alembic) ships with the
# server — nothing to install. /app/extensions is ours; the image does not use it.
COPY hindsight-extensions/rbac/hindsight_ext_rbac /app/extensions/hindsight_ext_rbac
ENV PYTHONPATH=/app/extensions

# Fail the build, rather than the first request, if the extension cannot be imported by
# the interpreter the server actually runs.
RUN /app/api/.venv/bin/python -c "import hindsight_ext_rbac"
