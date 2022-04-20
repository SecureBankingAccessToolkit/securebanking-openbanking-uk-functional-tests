package com.forgerock.securebanking.tests.functional.deprecated.registration

import assertk.assertThat
import assertk.assertions.containsExactly
import assertk.assertions.isEqualTo
import assertk.assertions.isNotNull
import com.forgerock.securebanking.framework.constants.OB_TPP_PRE_EIDAS_TRANSPORT_KEY_PATH
import com.forgerock.securebanking.framework.constants.OB_TPP_PRE_EIDAS_TRANSPORT_PEM_PATH
import com.forgerock.securebanking.framework.http.fuel.initFuel
import com.forgerock.securebanking.support.registration.registerTpp
import com.forgerock.securebanking.support.registration.signRegistrationRequest
import com.forgerock.securebanking.support.registration.unregisterTpp
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class OpenBankingDirectoryDynamicRegistrationTest {

    @BeforeEach
    fun setup() {
        initFuel(privatePem = OB_TPP_PRE_EIDAS_TRANSPORT_KEY_PATH, publicPem = OB_TPP_PRE_EIDAS_TRANSPORT_PEM_PATH)
    }

    @Test
    fun shouldUnregisterWhenUsingOpenBankingTransportKeys() {
        // Given
        val (signedRegistrationRequest, _) = signRegistrationRequest()
        val registrationResponse = registerTpp(signedRegistrationRequest)

        try {
            // When
            val (_, response, _) = unregisterTpp(registrationResponse.registration_access_token)

            // Then
            assertThat(response.statusCode).isEqualTo(200)
        } finally {
            unregisterTpp(registrationResponse.registration_access_token)
        }
    }

    @Test
    fun shouldRegisterWhenUsingOpenBankingTransportKeys() {
        // Given
        val (signedRegistrationRequest, registrationRequest) = signRegistrationRequest()

        // When
        val registrationResponse = registerTpp(signedRegistrationRequest)

        // Then
        try {
            assertThat(registrationResponse.client_id).isNotNull()
            assertThat(registrationResponse.redirect_uris).containsExactly(*registrationRequest.redirect_uris.toTypedArray())
        } finally {
            unregisterTpp(registrationResponse.registration_access_token)
        }
    }
}