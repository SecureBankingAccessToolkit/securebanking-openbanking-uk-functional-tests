package com.forgerock.uk.openbanking.tests.functional.payment.domestic.payments.consents.api.v3_1_8

import assertk.assertThat
import assertk.assertions.contains
import assertk.assertions.isEqualTo
import assertk.assertions.isNotEmpty
import assertk.assertions.isNotNull
import com.forgerock.securebanking.framework.conditions.Status
import com.forgerock.securebanking.framework.configuration.psu
import com.forgerock.securebanking.framework.data.AccessToken
import com.forgerock.securebanking.framework.extensions.junit.CreateTppCallback
import com.forgerock.securebanking.framework.http.fuel.defaultMapper
import com.forgerock.securebanking.framework.signature.signPayloadSubmitPayment
import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion
import com.forgerock.uk.openbanking.framework.constants.INVALID_FORMAT_DETACHED_JWS
import com.forgerock.uk.openbanking.framework.constants.INVALID_SIGNING_KID
import com.forgerock.uk.openbanking.framework.errors.INVALID_FORMAT_DETACHED_JWS_ERROR
import com.forgerock.uk.openbanking.framework.errors.NO_DETACHED_JWS
import com.forgerock.uk.openbanking.framework.errors.UNAUTHORIZED
import com.forgerock.uk.openbanking.support.discovery.getPaymentsApiLinks
import com.forgerock.uk.openbanking.support.payment.PaymentAS
import com.forgerock.uk.openbanking.support.payment.PaymentRS
import com.github.kittinunf.fuel.core.FuelError
import org.assertj.core.api.Assertions
import uk.org.openbanking.datamodel.payment.OBWriteDomesticConsent4
import uk.org.openbanking.datamodel.payment.OBWriteDomesticConsentResponse5
import uk.org.openbanking.testsupport.payment.OBWriteDomesticConsentTestDataFactory

class CreateDomesticPaymentsConsents(val version: OBVersion, val tppResource: CreateTppCallback.TppResource) {

    val paymentLinks = getPaymentsApiLinks(version)

    fun createDomesticPaymentsConsentsTest() {
        // Given
        val consentRequest = OBWriteDomesticConsentTestDataFactory.aValidOBWriteDomesticConsent4()
        val consent = createDomesticPaymentsConsent(consentRequest)

        // Then
        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)
        assertThat(consent.risk).isNotNull()
    }

    fun shouldCreateDomesticPaymentsConsents_throwsNoDetachedJwsTest() {
        // Given
        val consentRequest = OBWriteDomesticConsentTestDataFactory.aValidOBWriteDomesticConsent4()

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            PaymentRS().consentNoDetachedJwt<OBWriteDomesticConsentResponse5>(
                paymentLinks.CreateDomesticPaymentConsent,
                consentRequest,
                tppResource.tpp,
                version
            )
        }

        // Then
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(400)
        assertThat(exception.message.toString()).contains(NO_DETACHED_JWS)
    }

    fun shouldCreateDomesticPaymentsConsents_throwsNotPermittedB64HeaderAddedInTheDetachedJwsTest() {
        // Given
        val consentRequest = OBWriteDomesticConsentTestDataFactory.aValidOBWriteDomesticConsent4()

        val signedPayload =
            signPayloadSubmitPayment(
                defaultMapper.writeValueAsString(consentRequest),
                tppResource.tpp.signingKey,
                tppResource.tpp.signingKid,
                true
            )

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            PaymentRS().consent<OBWriteDomesticConsentResponse5>(
                paymentLinks.CreateDomesticPaymentConsent,
                consentRequest,
                tppResource.tpp,
                version,
                signedPayload
            )
        }

        // Then
        assertThat((exception.cause as FuelError).response.responseMessage).isEqualTo(UNAUTHORIZED)
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(401)
    }

    fun shouldCreateDomesticPaymentsConsents_throwsSendInvalidFormatDetachedJwsTest() {
        // Given
        val consentRequest = OBWriteDomesticConsentTestDataFactory.aValidOBWriteDomesticConsent4()

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            PaymentRS().consent<OBWriteDomesticConsentResponse5>(
                paymentLinks.CreateDomesticPaymentConsent,
                consentRequest,
                tppResource.tpp,
                version,
                INVALID_FORMAT_DETACHED_JWS
            )
        }

        // Then
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(400)
        assertThat(exception.message.toString()).contains(INVALID_FORMAT_DETACHED_JWS_ERROR)
    }

    fun shouldCreateDomesticPaymentsConsents_throwsSendInvalidKidDetachedJwsTest() {
        // Given
        val consentRequest = OBWriteDomesticConsentTestDataFactory.aValidOBWriteDomesticConsent4()

        val signedPayloadConsent =
            signPayloadSubmitPayment(
                defaultMapper.writeValueAsString(consentRequest),
                tppResource.tpp.signingKey,
                INVALID_SIGNING_KID
            )

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            PaymentRS().consent<OBWriteDomesticConsentResponse5>(
                paymentLinks.CreateDomesticPaymentConsent,
                consentRequest,
                tppResource.tpp,
                version,
                signedPayloadConsent
            )
        }

        // Then
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(401)
        assertThat((exception.cause as FuelError).response.responseMessage).isEqualTo(UNAUTHORIZED)
    }

    fun createDomesticPaymentsConsent(consentRequest: OBWriteDomesticConsent4): OBWriteDomesticConsentResponse5 {
        val signedPayloadConsent =
            signPayloadSubmitPayment(
                defaultMapper.writeValueAsString(consentRequest),
                tppResource.tpp.signingKey,
                tppResource.tpp.signingKid
            )

        // When
        val consent = PaymentRS().consent<OBWriteDomesticConsentResponse5>(
            paymentLinks.CreateDomesticPaymentConsent,
            consentRequest,
            tppResource.tpp,
            version,
            signedPayloadConsent
        )
        return consent
    }

    fun createDomesticPaymentsConsentAndGetAccessToken(consentRequest: OBWriteDomesticConsent4): Pair<OBWriteDomesticConsentResponse5, AccessToken> {
        val consent = createDomesticPaymentsConsent(consentRequest)
        val accessTokenAuthorizationCode = PaymentAS().getAccessToken(
            consent.data.consentId,
            tppResource.tpp.registrationResponse,
            psu,
            tppResource.tpp
        )
        return consent to accessTokenAuthorizationCode
    }
}