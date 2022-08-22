package com.forgerock.uk.openbanking.tests.functional.payment.domestic.payments.api.v3_1_8

import assertk.assertThat
import assertk.assertions.contains
import assertk.assertions.isEqualTo
import assertk.assertions.isNotEmpty
import assertk.assertions.isNotNull
import com.forgerock.securebanking.framework.conditions.Status
import com.forgerock.securebanking.framework.extensions.junit.CreateTppCallback
import com.forgerock.securebanking.framework.http.fuel.defaultMapper
import com.forgerock.securebanking.framework.signature.signPayloadSubmitPayment
import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion
import com.forgerock.uk.openbanking.framework.constants.INVALID_CONSENT_ID
import com.forgerock.uk.openbanking.framework.constants.INVALID_FORMAT_DETACHED_JWS
import com.forgerock.uk.openbanking.framework.constants.INVALID_SIGNING_KID
import com.forgerock.uk.openbanking.framework.errors.INVALID_FORMAT_DETACHED_JWS_ERROR
import com.forgerock.uk.openbanking.framework.errors.NO_DETACHED_JWS
import com.forgerock.uk.openbanking.framework.errors.PAYMENT_SUBMISSION_ALREADY_EXISTS
import com.forgerock.uk.openbanking.framework.errors.UNAUTHORIZED
import com.forgerock.uk.openbanking.support.payment.PaymentFactory
import com.forgerock.uk.openbanking.support.payment.PaymentRS
import com.forgerock.uk.openbanking.tests.functional.payment.domestic.payments.consents.api.v3_1_8.CreateDomesticPaymentsConsents
import com.github.kittinunf.fuel.core.FuelError
import org.assertj.core.api.Assertions
import uk.org.openbanking.datamodel.payment.OBWriteDataDomestic2
import uk.org.openbanking.datamodel.payment.OBWriteDomestic2
import uk.org.openbanking.datamodel.payment.OBWriteDomesticConsentResponse5
import uk.org.openbanking.datamodel.payment.OBWriteDomesticResponse5
import uk.org.openbanking.testsupport.payment.OBWriteDomesticConsentTestDataFactory

class CreateDomesticPayment(
    val version: OBVersion,
    val tppResource: CreateTppCallback.TppResource
) {

    private val createDomesticPaymentsConsentsApi = CreateDomesticPaymentsConsents(version, tppResource)

    fun createDomesticPaymentsTest() {
        // Given
        val consentRequest = OBWriteDomesticConsentTestDataFactory.aValidOBWriteDomesticConsent4()
        val (consent, accessToken) = createDomesticPaymentsConsentsApi.createDomesticPaymentsConsentAndGetAccessToken(
            consentRequest
        )

        val patchedConsent = PaymentRS().getConsent<OBWriteDomesticConsentResponse5>(
            PaymentFactory.urlWithConsentId(
                createDomesticPaymentsConsentsApi.paymentLinks.GetDomesticPaymentConsent,
                consent.data.consentId
            ),
            tppResource.tpp
        )

        assertThat(patchedConsent).isNotNull()
        assertThat(patchedConsent.data).isNotNull()
        assertThat(patchedConsent.data.initiation).isNotNull()
        assertThat(patchedConsent.risk).isNotNull()
        assertThat(patchedConsent.data.consentId).isNotEmpty()
        Assertions.assertThat(patchedConsent.data.status.toString()).`is`(Status.consentCondition)

        val paymentSubmissionRequest = OBWriteDomestic2().data(
            OBWriteDataDomestic2()
                .consentId(patchedConsent.data.consentId)
                .initiation(PaymentFactory.mapOBWriteDomestic2DataInitiationToOBDomestic2(patchedConsent.data.initiation))
        ).risk(patchedConsent.risk)

        val signedPayload = signPayloadSubmitPayment(
            defaultMapper.writeValueAsString(paymentSubmissionRequest),
            tppResource.tpp.signingKey,
            tppResource.tpp.signingKid
        )

        // When
        val result = PaymentRS().submitPayment<OBWriteDomesticResponse5>(
            createDomesticPaymentsConsentsApi.paymentLinks.CreateDomesticPayment,
            paymentSubmissionRequest,
            accessToken,
            signedPayload,
            tppResource.tpp,
            version
        )

        // Then
        assertThat(result).isNotNull()
        assertThat(result.data).isNotNull()
        assertThat(result.data.consentId).isNotEmpty()
    }

    fun shouldCreateDomesticPayments_throwsPaymentAlreadyExistsTest() {
        // Given
        val consentRequest = OBWriteDomesticConsentTestDataFactory.aValidOBWriteDomesticConsent4()
        val (consent, accessToken) = createDomesticPaymentsConsentsApi.createDomesticPaymentsConsentAndGetAccessToken(
            consentRequest
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)

        val patchedConsent = PaymentRS().getConsent<OBWriteDomesticConsentResponse5>(
            PaymentFactory.urlWithConsentId(
                createDomesticPaymentsConsentsApi.paymentLinks.GetDomesticPaymentConsent,
                consent.data.consentId
            ),
            tppResource.tpp
        )

        assertThat(patchedConsent).isNotNull()
        assertThat(patchedConsent.data).isNotNull()
        assertThat(patchedConsent.risk).isNotNull()
        assertThat(patchedConsent.data.consentId).isNotEmpty()
        Assertions.assertThat(patchedConsent.data.status.toString()).`is`(Status.consentCondition)

        val paymentSubmissionRequest = OBWriteDomestic2().data(
            OBWriteDataDomestic2()
                .consentId(patchedConsent.data.consentId)
                .initiation(PaymentFactory.mapOBWriteDomestic2DataInitiationToOBDomestic2(patchedConsent.data.initiation))
        ).risk(patchedConsent.risk)

        val signedPayload = signPayloadSubmitPayment(
            defaultMapper.writeValueAsString(paymentSubmissionRequest),
            tppResource.tpp.signingKey,
            tppResource.tpp.signingKid
        )
        // This will throw the error Payment already exist
        PaymentRS().submitPayment<OBWriteDomesticResponse5>(
            createDomesticPaymentsConsentsApi.paymentLinks.CreateDomesticPayment,
            paymentSubmissionRequest,
            accessToken,
            signedPayload,
            tppResource.tpp,
            version
        )

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            PaymentRS().submitPayment<OBWriteDomesticResponse5>(
                createDomesticPaymentsConsentsApi.paymentLinks.CreateDomesticPayment,
                paymentSubmissionRequest,
                accessToken,
                signedPayload,
                tppResource.tpp,
                version
            )
        }

        // Then
        assertThat(exception.message.toString()).contains(PAYMENT_SUBMISSION_ALREADY_EXISTS)
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(403)
    }

    fun shouldCreateDomesticPayments_throwsSendInvalidFormatDetachedJwsTest() {
        // Given
        val consentRequest = OBWriteDomesticConsentTestDataFactory.aValidOBWriteDomesticConsent4()
        val (consent, accessToken) = createDomesticPaymentsConsentsApi.createDomesticPaymentsConsentAndGetAccessToken(
            consentRequest
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)

        val patchedConsent = PaymentRS().getConsent<OBWriteDomesticConsentResponse5>(
            PaymentFactory.urlWithConsentId(
                createDomesticPaymentsConsentsApi.paymentLinks.GetDomesticPaymentConsent,
                consent.data.consentId
            ),
            tppResource.tpp
        )

        assertThat(patchedConsent).isNotNull()
        assertThat(patchedConsent.data).isNotNull()
        assertThat(patchedConsent.risk).isNotNull()
        assertThat(patchedConsent.data.consentId).isNotEmpty()
        Assertions.assertThat(patchedConsent.data.status.toString()).`is`(Status.consentCondition)

        val paymentSubmissionRequest = OBWriteDomestic2().data(
            OBWriteDataDomestic2()
                .consentId(patchedConsent.data.consentId)
                .initiation(PaymentFactory.mapOBWriteDomestic2DataInitiationToOBDomestic2(patchedConsent.data.initiation))
        ).risk(patchedConsent.risk)

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            PaymentRS().submitPayment<OBWriteDomesticResponse5>(
                createDomesticPaymentsConsentsApi.paymentLinks.CreateDomesticPayment,
                paymentSubmissionRequest,
                accessToken,
                INVALID_FORMAT_DETACHED_JWS,
                tppResource.tpp,
                version
            )
        }

        // Then
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(400)
        assertThat(exception.message.toString()).contains(INVALID_FORMAT_DETACHED_JWS_ERROR)
    }

    fun shouldCreateDomesticPayments_throwsNoDetachedJwsTest() {
        // Given
        val consentRequest = OBWriteDomesticConsentTestDataFactory.aValidOBWriteDomesticConsent4()
        val (consent, accessToken) = createDomesticPaymentsConsentsApi.createDomesticPaymentsConsentAndGetAccessToken(
            consentRequest
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)

        val patchedConsent = PaymentRS().getConsent<OBWriteDomesticConsentResponse5>(
            PaymentFactory.urlWithConsentId(
                createDomesticPaymentsConsentsApi.paymentLinks.GetDomesticPaymentConsent,
                consent.data.consentId
            ),
            tppResource.tpp,
            version
        )

        assertThat(patchedConsent).isNotNull()
        assertThat(patchedConsent.data).isNotNull()
        assertThat(patchedConsent.risk).isNotNull()
        assertThat(patchedConsent.data.consentId).isNotEmpty()
        Assertions.assertThat(patchedConsent.data.status.toString()).`is`(Status.consentCondition)

        val paymentSubmissionRequest = OBWriteDomestic2().data(
            OBWriteDataDomestic2()
                .consentId(patchedConsent.data.consentId)
                .initiation(PaymentFactory.mapOBWriteDomestic2DataInitiationToOBDomestic2(patchedConsent.data.initiation))
        ).risk(patchedConsent.risk)

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            PaymentRS().submitPaymentNoDetachedJws<OBWriteDomesticResponse5>(
                createDomesticPaymentsConsentsApi.paymentLinks.CreateDomesticPayment,
                paymentSubmissionRequest,
                accessToken
            )
        }

        // Then
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(400)
        assertThat(exception.message.toString()).contains(NO_DETACHED_JWS)
    }

    fun shouldCreateDomesticPayments_throwsNotPermittedB64HeaderAddedInTheDetachedJwsTest() {
        // Given
        val consentRequest = OBWriteDomesticConsentTestDataFactory.aValidOBWriteDomesticConsent4()
        val (consent, accessToken) = createDomesticPaymentsConsentsApi.createDomesticPaymentsConsentAndGetAccessToken(
            consentRequest
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)

        val patchedConsent = PaymentRS().getConsent<OBWriteDomesticConsentResponse5>(
            PaymentFactory.urlWithConsentId(
                createDomesticPaymentsConsentsApi.paymentLinks.GetDomesticPaymentConsent,
                consent.data.consentId
            ),
            tppResource.tpp
        )

        assertThat(patchedConsent).isNotNull()
        assertThat(patchedConsent.data).isNotNull()
        assertThat(patchedConsent.risk).isNotNull()
        assertThat(patchedConsent.data.consentId).isNotEmpty()
        Assertions.assertThat(patchedConsent.data.status.toString()).`is`(Status.consentCondition)

        val paymentSubmissionRequest = OBWriteDomestic2().data(
            OBWriteDataDomestic2()
                .consentId(patchedConsent.data.consentId)
                .initiation(PaymentFactory.mapOBWriteDomestic2DataInitiationToOBDomestic2(patchedConsent.data.initiation))
        ).risk(patchedConsent.risk)

        val signedPayload =
            signPayloadSubmitPayment(
                defaultMapper.writeValueAsString(paymentSubmissionRequest),
                tppResource.tpp.signingKey,
                tppResource.tpp.signingKid,
                true
            )

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            PaymentRS().submitPayment<OBWriteDomesticResponse5>(
                createDomesticPaymentsConsentsApi.paymentLinks.CreateDomesticPayment,
                paymentSubmissionRequest,
                accessToken,
                signedPayload,
                tppResource.tpp,
                version
            )
        }

        // Then
        assertThat((exception.cause as FuelError).response.responseMessage).isEqualTo(UNAUTHORIZED)
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(401)
    }

    fun shouldCreateDomesticPayments_throwsSendInvalidKidDetachedJwsTest() {
        // Given
        val consentRequest = OBWriteDomesticConsentTestDataFactory.aValidOBWriteDomesticConsent4()
        val (consent, accessToken) = createDomesticPaymentsConsentsApi.createDomesticPaymentsConsentAndGetAccessToken(
            consentRequest
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)

        val patchedConsent = PaymentRS().getConsent<OBWriteDomesticConsentResponse5>(
            PaymentFactory.urlWithConsentId(
                createDomesticPaymentsConsentsApi.paymentLinks.GetDomesticPaymentConsent,
                consent.data.consentId
            ),
            tppResource.tpp
        )

        assertThat(patchedConsent).isNotNull()
        assertThat(patchedConsent.data).isNotNull()
        assertThat(patchedConsent.risk).isNotNull()
        assertThat(patchedConsent.data.consentId).isNotEmpty()
        Assertions.assertThat(patchedConsent.data.status.toString()).`is`(Status.consentCondition)

        val paymentSubmissionRequest = OBWriteDomestic2().data(
            OBWriteDataDomestic2()
                .consentId(patchedConsent.data.consentId)
                .initiation(PaymentFactory.mapOBWriteDomestic2DataInitiationToOBDomestic2(patchedConsent.data.initiation))
        ).risk(patchedConsent.risk)

        val signedPayload =
            signPayloadSubmitPayment(
                defaultMapper.writeValueAsString(paymentSubmissionRequest),
                tppResource.tpp.signingKey,
                INVALID_SIGNING_KID
            )

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            PaymentRS().submitPayment<OBWriteDomesticResponse5>(
                createDomesticPaymentsConsentsApi.paymentLinks.CreateDomesticPayment,
                paymentSubmissionRequest,
                accessToken,
                signedPayload,
                tppResource.tpp,
                version
            )
        }

        // Then
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(401)
        assertThat((exception.cause as FuelError).response.responseMessage).isEqualTo(UNAUTHORIZED)
    }

    fun shouldCreateDomesticPayments_throwsInvalidDetachedJws_detachedJwsHasDifferentConsentIdThanTheBodyTest() {
        // Given
        val consentRequest = OBWriteDomesticConsentTestDataFactory.aValidOBWriteDomesticConsent4()
        val (consent, accessToken) = createDomesticPaymentsConsentsApi.createDomesticPaymentsConsentAndGetAccessToken(
            consentRequest
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)

        val patchedConsent = PaymentRS().getConsent<OBWriteDomesticConsentResponse5>(
            PaymentFactory.urlWithConsentId(
                createDomesticPaymentsConsentsApi.paymentLinks.GetDomesticPaymentConsent,
                consent.data.consentId
            ),
            tppResource.tpp
        )

        assertThat(patchedConsent).isNotNull()
        assertThat(patchedConsent.data).isNotNull()
        assertThat(patchedConsent.risk).isNotNull()
        assertThat(patchedConsent.data.consentId).isNotEmpty()
        Assertions.assertThat(patchedConsent.data.status.toString()).`is`(Status.consentCondition)

        val paymentSubmissionRequest = OBWriteDomestic2().data(
            OBWriteDataDomestic2()
                .consentId(patchedConsent.data.consentId)
                .initiation(PaymentFactory.mapOBWriteDomestic2DataInitiationToOBDomestic2(patchedConsent.data.initiation))
        ).risk(patchedConsent.risk)

        patchedConsent.data.consentId = INVALID_CONSENT_ID
        val paymentSubmissionWithInvalidConsentId = OBWriteDomestic2().data(
            OBWriteDataDomestic2()
                .consentId(patchedConsent.data.consentId)
                .initiation(PaymentFactory.mapOBWriteDomestic2DataInitiationToOBDomestic2(patchedConsent.data.initiation))
        ).risk(patchedConsent.risk)

        val signedPayload = signPayloadSubmitPayment(
            defaultMapper.writeValueAsString(paymentSubmissionWithInvalidConsentId),
            tppResource.tpp.signingKey,
            tppResource.tpp.signingKid
        )

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            PaymentRS().submitPayment<OBWriteDomesticResponse5>(
                createDomesticPaymentsConsentsApi.paymentLinks.CreateDomesticPayment,
                paymentSubmissionRequest,
                accessToken,
                signedPayload,
                tppResource.tpp,
                version
            )
        }

        // Then
        assertThat((exception.cause as FuelError).response.responseMessage).isEqualTo(UNAUTHORIZED)
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(401)
    }

    fun shouldCreateDomesticPayments_throwsInvalidDetachedJws_detachedJwsHasDifferentAmountThanTheBodyTest() {
        // Given
        val consentRequest = OBWriteDomesticConsentTestDataFactory.aValidOBWriteDomesticConsent4()
        val (consent, accessToken) = createDomesticPaymentsConsentsApi.createDomesticPaymentsConsentAndGetAccessToken(
            consentRequest
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)

        val patchedConsent = PaymentRS().getConsent<OBWriteDomesticConsentResponse5>(
            PaymentFactory.urlWithConsentId(
                createDomesticPaymentsConsentsApi.paymentLinks.GetDomesticPaymentConsent,
                consent.data.consentId
            ),
            tppResource.tpp
        )

        assertThat(patchedConsent).isNotNull()
        assertThat(patchedConsent.data).isNotNull()
        assertThat(patchedConsent.risk).isNotNull()
        assertThat(patchedConsent.data.consentId).isNotEmpty()
        Assertions.assertThat(patchedConsent.data.status.toString()).`is`(Status.consentCondition)

        val paymentSubmissionRequest = OBWriteDomestic2().data(
            OBWriteDataDomestic2()
                .consentId(patchedConsent.data.consentId)
                .initiation(PaymentFactory.mapOBWriteDomestic2DataInitiationToOBDomestic2(patchedConsent.data.initiation))
        ).risk(patchedConsent.risk)

        patchedConsent.data.initiation.instructedAmount.amount = "123123"
        val paymentSubmissionInvalidAmount = OBWriteDomestic2().data(
            OBWriteDataDomestic2()
                .consentId(patchedConsent.data.consentId)
                .initiation(PaymentFactory.mapOBWriteDomestic2DataInitiationToOBDomestic2(patchedConsent.data.initiation))
        ).risk(patchedConsent.risk)

        val signedPayload = signPayloadSubmitPayment(
            defaultMapper.writeValueAsString(paymentSubmissionInvalidAmount),
            tppResource.tpp.signingKey,
            tppResource.tpp.signingKid
        )

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            PaymentRS().submitPayment<OBWriteDomesticResponse5>(
                createDomesticPaymentsConsentsApi.paymentLinks.CreateDomesticPayment,
                paymentSubmissionRequest,
                accessToken,
                signedPayload,
                tppResource.tpp,
                version
            )
        }

        // Then
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(401)
        assertThat((exception.cause as FuelError).response.responseMessage).isEqualTo(UNAUTHORIZED)
    }
}