package com.forgerock.sapi.gateway.framework.data

import com.forgerock.sapi.gateway.framework.configuration.CLIENT_AUTH_METHOD
import com.forgerock.sapi.gateway.framework.configuration.REDIRECT_URI
import com.forgerock.sapi.gateway.ob.uk.support.discovery.asDiscovery
import com.forgerock.sapi.gateway.uk.common.shared.api.meta.obie.OBConstants

data class RegistrationRequest(
        val software_statement: String,
        val iss: String = com.forgerock.sapi.gateway.ob.uk.framework.configuration.OB_SOFTWARE_ID,
        val iat: Long = (System.currentTimeMillis() / 1000),
        val exp: Long = (System.currentTimeMillis() / 1000) + 180,
        val grant_types: List<String> = asDiscovery.grant_types_supported,
        val id_token_signed_response_alg: String = "PS256",
        val redirect_uris: List<String> = listOf(REDIRECT_URI),
        val request_object_encryption_alg: String = "RSA-OAEP-256",
        val request_object_encryption_enc: String? = null,
        val request_object_signing_alg: String = "PS256",
        val response_types: List<String> = listOf("code id_token"),
        val scope: String = asDiscovery.scopes_supported.intersect(
                listOf(
                        OBConstants.Scope.OPENID,
                        OBConstants.Scope.ACCOUNTS,
                        OBConstants.Scope.PAYMENTS,
                        OBConstants.Scope.FUNDS_CONFIRMATIONS,
                        OBConstants.Scope.EVENT_POLLING
                )
        ).joinToString(separator = " "),

        val subject_type: String = "pairwise",
        val token_endpoint_auth_method: String = CLIENT_AUTH_METHOD,
        val token_endpoint_auth_signing_alg: String = "PS256",
        val tls_client_auth_subject_dn: String
)

data class RegistrationResponse(
        val application_type: String,
        val client_id: String,
        val client_secret: String? = null,
        val client_secret_expires_at: String? = null,
        val default_max_age: String,
        val grant_types: List<String>,
        val id_token_encrypted_response_alg: String,
        val id_token_encrypted_response_enc: String,
        val id_token_signed_response_alg: String,
        val jwks_uri: String,
        val redirect_uris: List<String>,
        val registration_access_token: String,
        val registration_client_uri: String,
        val request_object_encryption_alg: String,
        val request_object_encryption_enc: String?,
        val request_object_signing_alg: String,
        val response_types: List<String>,
        val scope: String,
        val scopes: List<String>,
        val subject_type: String,
        val token_endpoint_auth_method: String,
        val token_endpoint_auth_signing_alg: String,
        val userinfo_encrypted_response_alg: String,
        val userinfo_encrypted_response_enc: String,
        val userinfo_signed_response_alg: String,
        val introspection_encrypted_response_alg: String,
        val introspection_encrypted_response_enc: String,
        val introspection_signed_response_alg: String,
        val client_type: String,
        val public_key_selector: String,
        val authorization_code_lifetime: Long,
        val user_info_response_format_selector: String,
        val tls_client_certificate_bound_access_tokens: Boolean,
        val backchannel_logout_session_required: Boolean,
        val default_max_age_enabled: Boolean,
        val token_intro_response_format_selector: String,
        val jwt_token_lifetime: Long,
        val id_token_encryption_enabled: Boolean,
        val access_token_lifetime: Long,
        val refresh_token_lifetime: Long,
        val software_statement: String? = null
)
