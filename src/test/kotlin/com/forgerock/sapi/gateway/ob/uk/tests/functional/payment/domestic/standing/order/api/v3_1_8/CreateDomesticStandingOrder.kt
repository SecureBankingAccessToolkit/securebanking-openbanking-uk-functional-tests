package com.forgerock.sapi.gateway.ob.uk.tests.functional.payment.domestic.standing.order.api.v3_1_8

import assertk.assertThat
import assertk.assertions.contains
import assertk.assertions.isEqualTo
import assertk.assertions.isNotEmpty
import assertk.assertions.isNotNull
import com.forgerock.sapi.gateway.framework.conditions.Status
import com.forgerock.sapi.gateway.framework.data.AccessToken
import com.forgerock.sapi.gateway.framework.extensions.junit.CreateTppCallback
import com.forgerock.sapi.gateway.framework.http.fuel.defaultMapper
import com.forgerock.sapi.gateway.ob.uk.support.discovery.getPaymentsApiLinks
import com.forgerock.sapi.gateway.ob.uk.support.payment.BadJwsSignatureProducer
import com.forgerock.sapi.gateway.ob.uk.support.payment.DefaultJwsSignatureProducer
import com.forgerock.sapi.gateway.ob.uk.support.payment.InvalidKidJwsSignatureProducer
import com.forgerock.sapi.gateway.ob.uk.support.payment.PaymentFactory.Companion.mapOBWriteDomesticStandingOrderConsentResponse6DataInitiationToOBWriteDomesticStandingOrder3DataInitiation
import com.forgerock.sapi.gateway.uk.common.shared.api.meta.obie.OBVersion
import com.forgerock.sapi.gateway.ob.uk.tests.functional.payment.domestic.standing.order.consents.api.v3_1_8.CreateDomesticStandingOrderConsents
import com.github.kittinunf.fuel.core.FuelError
import org.assertj.core.api.Assertions
import uk.org.openbanking.datamodel.payment.*
import uk.org.openbanking.testsupport.payment.OBWriteDomesticStandingOrderConsentTestDataFactory

class CreateDomesticStandingOrder(val version: OBVersion, val tppResource: CreateTppCallback.TppResource) {

    private val createDomesticStandingOrderConsentsApi = CreateDomesticStandingOrderConsents(version, tppResource)
    private val paymentApiClient = tppResource.tpp.paymentApiClient
    private val paymentLinks = getPaymentsApiLinks(version)
    private val createPaymentUrl = paymentLinks.CreateDomesticStandingOrder

    fun createDomesticStandingOrderTest() {
        // Given
        val consentRequest =
            OBWriteDomesticStandingOrderConsentTestDataFactory.aValidOBWriteDomesticStandingOrderConsent5()
        // When
        val result = submitStandingOrder(consentRequest)

        // Then
        assertThat(result).isNotNull()
        assertThat(result.data).isNotNull()
        assertThat(result.data.charges).isNotNull().isNotEmpty()
        assertThat(result.data.consentId).isNotEmpty()
        assertThat(result.links.self.toString()).isEqualTo(createPaymentUrl + "/" + result.data.domesticStandingOrderId)
    }

    fun createDomesticStandingOrder_mandatoryFieldsTest() {
        // Given
        val consentRequest =
            OBWriteDomesticStandingOrderConsentTestDataFactory.aValidOBWriteDomesticStandingOrderConsent5MandatoryFields()
        // When
        val result = submitStandingOrder(consentRequest)

        // Then
        assertThat(result).isNotNull()
        assertThat(result.data).isNotNull()
        assertThat(result.data.consentId).isNotEmpty()
    }

    fun shouldCreateDomesticStandingOrder_throwsStandingOrderAlreadyExistsTest() {
        // Given
        val consentRequest =
            OBWriteDomesticStandingOrderConsentTestDataFactory.aValidOBWriteDomesticStandingOrderConsent5()
        val (consent, accessTokenAuthorizationCode) = createDomesticStandingOrderConsentsApi.createDomesticStandingOrderConsentAndAuthorize(
            consentRequest
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)

        // When
        val patchedConsent = getPatchedConsent(consent)
        // Submit first payment
        submitStandingOrderForPatchedConsent(patchedConsent, accessTokenAuthorizationCode)

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            // Verify we fail to submit a second payment
            submitStandingOrderForPatchedConsent(patchedConsent, accessTokenAuthorizationCode)
        }

        // Then
        assertThat(exception.message.toString()).contains(com.forgerock.sapi.gateway.ob.uk.framework.errors.PAYMENT_SUBMISSION_ALREADY_EXISTS)
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(403)
    }

    fun shouldCreateDomesticStandingOrder_throwsSendInvalidFormatDetachedJwsTest() {
        // Given
        val consentRequest =
            OBWriteDomesticStandingOrderConsentTestDataFactory.aValidOBWriteDomesticStandingOrderConsent5()
        val (consent, accessTokenAuthorizationCode) = createDomesticStandingOrderConsentsApi.createDomesticStandingOrderConsentAndAuthorize(
            consentRequest
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)

        val paymentSubmissionRequest = createStandingOrderRequest(getPatchedConsent(consent))

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            paymentApiClient.buildSubmitPaymentRequest(createPaymentUrl, accessTokenAuthorizationCode, paymentSubmissionRequest)
                .configureJwsSignatureProducer(BadJwsSignatureProducer()).sendRequest()
        }

        // Then
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(400)
        assertThat(exception.message.toString()).contains(com.forgerock.sapi.gateway.ob.uk.framework.errors.INVALID_FORMAT_DETACHED_JWS_ERROR)
    }

    fun shouldCreateDomesticStandingOrder_throwsNoDetachedJwsTest() {
        // Given
        val consentRequest =
            OBWriteDomesticStandingOrderConsentTestDataFactory.aValidOBWriteDomesticStandingOrderConsent5()
        val (consent, accessTokenAuthorizationCode) = createDomesticStandingOrderConsentsApi.createDomesticStandingOrderConsentAndAuthorize(
            consentRequest
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)

        val paymentSubmissionRequest = createStandingOrderRequest(getPatchedConsent(consent))

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            paymentApiClient.buildSubmitPaymentRequest(createPaymentUrl, accessTokenAuthorizationCode, paymentSubmissionRequest)
                .configureJwsSignatureProducer(null).sendRequest()
        }

        // Then
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(400)
        assertThat(exception.message.toString()).contains(com.forgerock.sapi.gateway.ob.uk.framework.errors.NO_DETACHED_JWS)
    }

    fun shouldCreateDomesticStandingOrder_throwsNotPermittedB64HeaderAddedInTheDetachedJwsTest() {
        // Given
        val consentRequest =
            OBWriteDomesticStandingOrderConsentTestDataFactory.aValidOBWriteDomesticStandingOrderConsent5()
        val (consent, accessTokenAuthorizationCode) = createDomesticStandingOrderConsentsApi.createDomesticStandingOrderConsentAndAuthorize(
            consentRequest
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)

        val paymentSubmissionRequest = createStandingOrderRequest(getPatchedConsent(consent))

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            paymentApiClient.buildSubmitPaymentRequest(createPaymentUrl, accessTokenAuthorizationCode, paymentSubmissionRequest)
                .configureJwsSignatureProducer(DefaultJwsSignatureProducer(tppResource.tpp, false)).sendRequest()
        }

        // Then
        assertThat((exception.cause as FuelError).response.responseMessage).isEqualTo(com.forgerock.sapi.gateway.ob.uk.framework.errors.UNAUTHORIZED)
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(401)
    }

    fun shouldCreateDomesticStandingOrder_throwsSendInvalidKidDetachedJwsTest() {
        // Given
        val consentRequest =
            OBWriteDomesticStandingOrderConsentTestDataFactory.aValidOBWriteDomesticStandingOrderConsent5()
        val (consent, accessTokenAuthorizationCode) = createDomesticStandingOrderConsentsApi.createDomesticStandingOrderConsentAndAuthorize(
            consentRequest
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)

        val paymentSubmissionRequest = createStandingOrderRequest(getPatchedConsent(consent))

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            paymentApiClient.buildSubmitPaymentRequest(createPaymentUrl, accessTokenAuthorizationCode, paymentSubmissionRequest)
                .configureJwsSignatureProducer(InvalidKidJwsSignatureProducer(tppResource.tpp)).sendRequest()
        }

        // Then
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(401)
        assertThat((exception.cause as FuelError).response.responseMessage).isEqualTo(com.forgerock.sapi.gateway.ob.uk.framework.errors.UNAUTHORIZED)
    }

    fun shouldCreateDomesticStandingOrder_throwsInvalidDetachedJws_detachedJwsHasDifferentConsentIdThanTheBodyTest() {
        // Given
        val consentRequest =
            OBWriteDomesticStandingOrderConsentTestDataFactory.aValidOBWriteDomesticStandingOrderConsent5()
        val (consent, accessTokenAuthorizationCode) = createDomesticStandingOrderConsentsApi.createDomesticStandingOrderConsentAndAuthorize(
            consentRequest
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)

        val patchedConsent = getPatchedConsent(consent)
        val standingOrderSubmissionRequest = createStandingOrderRequest(patchedConsent)

        patchedConsent.data.consentId = com.forgerock.sapi.gateway.ob.uk.framework.constants.INVALID_CONSENT_ID
        val standingOrderSubmissionRequestWithInvalidConsentId = createStandingOrderRequest(patchedConsent)

        val signatureWithInvalidConsentId = DefaultJwsSignatureProducer(tppResource.tpp).createDetachedSignature(
            defaultMapper.writeValueAsString(standingOrderSubmissionRequestWithInvalidConsentId)
        )

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            paymentApiClient.buildSubmitPaymentRequest(createPaymentUrl, accessTokenAuthorizationCode, standingOrderSubmissionRequest)
                .configureJwsSignatureProducer(BadJwsSignatureProducer(signatureWithInvalidConsentId)).sendRequest()
        }

        // Then
        assertThat((exception.cause as FuelError).response.responseMessage).isEqualTo(com.forgerock.sapi.gateway.ob.uk.framework.errors.UNAUTHORIZED)
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(401)
    }

    fun shouldCreateDomesticStandingOrder_throwsInvalidDetachedJws_detachedJwsHasDifferentAmountThanTheBodyTest() {
        // Given
        val consentRequest =
            OBWriteDomesticStandingOrderConsentTestDataFactory.aValidOBWriteDomesticStandingOrderConsent5()
        val (consent, accessTokenAuthorizationCode) = createDomesticStandingOrderConsentsApi.createDomesticStandingOrderConsentAndAuthorize(
            consentRequest
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)

        val patchedConsent = getPatchedConsent(consent)
        val paymentSubmissionRequest = createStandingOrderRequest(patchedConsent)

        patchedConsent.data.initiation.firstPaymentAmount.amount = "123123"
        val paymentSubmissionInvalidAmount = createStandingOrderRequest(patchedConsent)

        val signatureWithInvalidAmount = DefaultJwsSignatureProducer(tppResource.tpp).createDetachedSignature(
            defaultMapper.writeValueAsString(paymentSubmissionInvalidAmount)
        )

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            paymentApiClient.buildSubmitPaymentRequest(createPaymentUrl, accessTokenAuthorizationCode, paymentSubmissionRequest)
                .configureJwsSignatureProducer(BadJwsSignatureProducer(signatureWithInvalidAmount)).sendRequest()
        }

        // Then
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(401)
        assertThat((exception.cause as FuelError).response.responseMessage).isEqualTo(com.forgerock.sapi.gateway.ob.uk.framework.errors.UNAUTHORIZED)
    }

    fun submitStandingOrder(consentRequest: OBWriteDomesticStandingOrderConsent5): OBWriteDomesticStandingOrderResponse6 {
        val (consent, authorizationToken) = createDomesticStandingOrderConsentsApi.createDomesticStandingOrderConsentAndAuthorize(
            consentRequest
        )
        return submitStandingOrder(consent, authorizationToken)
    }

    fun submitStandingOrder(
        consentResponse: OBWriteDomesticStandingOrderConsentResponse6,
        authorizationToken: AccessToken
    ): OBWriteDomesticStandingOrderResponse6 {
        val patchedConsent = getPatchedConsent(consentResponse)
        return submitStandingOrderForPatchedConsent(patchedConsent, authorizationToken)
    }

    private fun getPatchedConsent(consent: OBWriteDomesticStandingOrderConsentResponse6): OBWriteDomesticStandingOrderConsentResponse6 {
        return createDomesticStandingOrderConsentsApi.getPatchedConsent(consent)
    }

    private fun submitStandingOrderForPatchedConsent(
        patchedConsent: OBWriteDomesticStandingOrderConsentResponse6,
        authorizationToken: AccessToken
    ): OBWriteDomesticStandingOrderResponse6 {
        val paymentSubmissionRequest = createStandingOrderRequest(patchedConsent)
        return paymentApiClient.submitPayment(
            createPaymentUrl,
            authorizationToken,
            paymentSubmissionRequest
        )
    }

    private fun createStandingOrderRequest(patchedConsent: OBWriteDomesticStandingOrderConsentResponse6): OBWriteDomesticStandingOrder3 {
        return OBWriteDomesticStandingOrder3().data(
            OBWriteDomesticStandingOrder3Data()
                .consentId(patchedConsent.data.consentId)
                .initiation(mapOBWriteDomesticStandingOrderConsentResponse6DataInitiationToOBWriteDomesticStandingOrder3DataInitiation(patchedConsent.data.initiation))
        ).risk(patchedConsent.risk)
    }
}
