package com.forgerock.sapi.gateway.ob.uk.tests.functional.payment.domestic.standing.order.consents.api.v4_0_0

import assertk.assertThat
import assertk.assertions.contains
import assertk.assertions.isEqualTo
import assertk.assertions.isNotEmpty
import assertk.assertions.isNotNull
import com.forgerock.sapi.gateway.framework.conditions.StatusV4
import com.forgerock.sapi.gateway.framework.configuration.psu
import com.forgerock.sapi.gateway.framework.data.AccessToken
import com.forgerock.sapi.gateway.framework.extensions.junit.CreateTppCallback
import com.forgerock.sapi.gateway.ob.uk.framework.consent.ConsentFactoryRegistryHolder
import com.forgerock.sapi.gateway.ob.uk.framework.consent.payment.v4.OBWriteDomesticStandingOrderConsent5Factory
import com.forgerock.sapi.gateway.ob.uk.support.discovery.getPaymentsApiLinks
import com.forgerock.sapi.gateway.ob.uk.support.payment.*
import com.forgerock.sapi.gateway.uk.common.shared.api.meta.obie.OBVersion
import com.github.kittinunf.fuel.core.FuelError
import org.assertj.core.api.Assertions
import uk.org.openbanking.datamodel.v4.payment.OBWriteDomesticStandingOrder3DataInitiationDebtorAccount
import uk.org.openbanking.datamodel.v4.payment.OBWriteDomesticStandingOrderConsent5
import uk.org.openbanking.datamodel.v4.payment.OBWriteDomesticStandingOrderConsentResponse6
import java.util.*

class CreateDomesticStandingOrderConsents(val version: OBVersion, val tppResource: CreateTppCallback.TppResource) {

    private val paymentLinks = getPaymentsApiLinks(version)
    private val paymentApiClient = tppResource.tpp.paymentApiClient
    private val consentFactory = ConsentFactoryRegistryHolder.consentFactoryRegistry.getConsentFactory(
        OBWriteDomesticStandingOrderConsent5Factory::class.java
    )

    fun createDomesticStandingOrdersConsentsTest() {
        // Given
        val consentRequest = consentFactory.createConsent()
        val consent = createDomesticStandingOrderConsent(consentRequest)

        // Then
        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(StatusV4.consentCondition)
        assertThat(consent.risk).isNotNull()
    }

    fun createDomesticPaymentsConsents_SameIdempotencyKeyMultipleRequestTest() {
        // Given
        val consentRequest = consentFactory.createConsent()
        val idempotencyKey = UUID.randomUUID().toString()

        // when
        // first request
        val consentResponse1 = paymentApiClient.newPostRequestBuilder(
            paymentLinks.CreateDomesticStandingOrderConsent,
            tppResource.tpp.getClientCredentialsAccessToken(defaultPaymentScopesForAccessToken),
            consentRequest
        ).addIdempotencyKeyHeader(idempotencyKey).sendRequest<OBWriteDomesticStandingOrderConsentResponse6>()
        // second request with the same idempotencyKey
        val consentResponse2 = paymentApiClient.newPostRequestBuilder(
            paymentLinks.CreateDomesticStandingOrderConsent,
            tppResource.tpp.getClientCredentialsAccessToken(defaultPaymentScopesForAccessToken),
            consentRequest
        ).addIdempotencyKeyHeader(idempotencyKey).sendRequest<OBWriteDomesticStandingOrderConsentResponse6>()

        // Then
        assertThat(consentResponse1).isNotNull()
        assertThat(consentResponse1.data).isNotNull()
        assertThat(consentResponse1.data.consentId).isNotEmpty()
        Assertions.assertThat(consentResponse1.data.status.toString()).`is`(StatusV4.consentCondition)
        assertThat(consentResponse1.risk).isNotNull()

        assertThat(consentResponse2).isNotNull()
        assertThat(consentResponse2.data).isNotNull()
        assertThat(consentResponse2.data.consentId).isNotEmpty()
        Assertions.assertThat(consentResponse2.data.status.toString()).`is`(StatusV4.consentCondition)
        assertThat(consentResponse2.risk).isNotNull()

        assertThat(consentResponse1.data.consentId).isEqualTo(consentResponse2.data.consentId)
    }

    fun createDomesticStandingOrdersConsents_NoIdempotencyKey_throwsBadRequestTest() {
        // Given
        val consentRequest = consentFactory.createConsent()

        // when
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            paymentApiClient.newPostRequestBuilder(
                paymentLinks.CreateDomesticStandingOrderConsent,
                tppResource.tpp.getClientCredentialsAccessToken(defaultPaymentScopesForAccessToken),
                consentRequest
            ).deleteIdempotencyKeyHeader().sendRequest<OBWriteDomesticStandingOrderConsentResponse6>()
        }

        // Then
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(400)
        assertThat((exception.cause as FuelError).response.body()).isNotNull()
        assertThat(exception.message.toString()).contains("\"Errors\":[{\"ErrorCode\":\"U007\",\"Message\":\"Required request header 'x-idempotency-key' for method parameter type String is not present")
    }

    fun createDomesticStandingOrdersConsents_withDebtorAccountTest() {
        // Given
        val consentRequest = consentFactory.createConsent()

        // optional debtor account
        val debtorAccount = PsuData().getDebtorAccount()
        consentRequest.data.initiation.debtorAccount(
            OBWriteDomesticStandingOrder3DataInitiationDebtorAccount()
                .identification(debtorAccount.Identification)
                .schemeName(debtorAccount.SchemeName)
                .secondaryIdentification(debtorAccount.SecondaryIdentification)
        )

        val consent = createDomesticStandingOrderConsent(consentRequest)

        // Then
        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(StatusV4.consentCondition)
        assertThat(consent.risk).isNotNull()
    }

    fun createDomesticStandingOrdersConsents_throwsInvalidDebtorAccountTest() {
        // Given
        val consentRequest = consentFactory.createConsent()
        // optional debtor account (wrong debtor account)
        consentRequest.data.initiation.debtorAccount(
            OBWriteDomesticStandingOrder3DataInitiationDebtorAccount()
                .identification("Identification")
                .name("name")
                .schemeName("SchemeName")
                .secondaryIdentification("SecondaryIdentification")
        )

        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            createDomesticStandingOrderConsent(consentRequest)
        }

        // Then
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(400)
        assertThat((exception.cause as FuelError).response.body()).isNotNull()
        assertThat(exception.message.toString()).contains("Invalid debtor account")
    }

    fun createDomesticStandingOrdersConsents_mandatoryFields() {
        // Given
        val consentRequest =
            consentFactory.createConsentWithOnlyMandatoryFieldsPopulated()
        val consent = createDomesticStandingOrderConsent(consentRequest)

        // Then
        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(StatusV4.consentCondition)
        assertThat(consent.risk).isNotNull()
    }

    fun shouldCreateDomesticStandingOrdersConsents_throwsSendInvalidFormatDetachedJwsTest() {
        // Given
        val consentRequest = consentFactory.createConsent()

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            buildCreateConsentRequest(consentRequest).configureJwsSignatureProducer(BadJwsSignatureProducer())
                .sendRequest()
        }

        // Then
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(400)
        assertThat(exception.message.toString()).contains(com.forgerock.sapi.gateway.ob.uk.framework.errors.INVALID_FORMAT_DETACHED_JWS_ERROR)
    }

    fun shouldCreateDomesticStandingOrdersConsents_throwsNoDetachedJws() {
        // Given
        val consentRequest = consentFactory.createConsent()

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            buildCreateConsentRequest(consentRequest).configureJwsSignatureProducer(null).sendRequest()
        }

        // Then
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(400)
        assertThat(exception.message.toString()).contains(com.forgerock.sapi.gateway.ob.uk.framework.errors.NO_DETACHED_JWS)
    }

    fun shouldCreateDomesticStandingOrdersConsents_throwsNotPermittedB64HeaderAddedInTheDetachedJwsTest() {
        // Given
        val consentRequest = consentFactory.createConsent()

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            buildCreateConsentRequest(consentRequest).configureJwsSignatureProducer(
                DefaultJwsSignatureProducer(
                    tppResource.tpp,
                    false
                )
            ).sendRequest()
        }

        // Then
        assertThat((exception.cause as FuelError).response.responseMessage).isEqualTo(com.forgerock.sapi.gateway.ob.uk.framework.errors.UNAUTHORIZED)
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(401)
    }

    fun shouldCreateDomesticStandingOrdersConsents_throwsSendInvalidKidDetachedJwsTest() {
        // Given
        val consentRequest = consentFactory.createConsent()

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            buildCreateConsentRequest(consentRequest).configureJwsSignatureProducer(
                InvalidKidJwsSignatureProducer(
                    tppResource.tpp
                )
            ).sendRequest()
        }

        // Then
        assertThat((exception.cause as FuelError).response.statusCode).isEqualTo(401)
        assertThat((exception.cause as FuelError).response.responseMessage).isEqualTo(com.forgerock.sapi.gateway.ob.uk.framework.errors.UNAUTHORIZED)
    }

    fun shouldCreateDomesticStandingOrdersConsents_throwsRejectedConsentTest() {
        // Given
        val consentRequest = consentFactory.createConsent()

        // When
        val exception = org.junit.jupiter.api.Assertions.assertThrows(AssertionError::class.java) {
            createDomesticStandingOrderConsentAndReject(
                consentRequest
            )
        }

        // Then
        assertThat(exception.message.toString()).contains(com.forgerock.sapi.gateway.ob.uk.framework.errors.CONSENT_NOT_AUTHORISED)
    }

    fun createDomesticStandingOrderConsent(consentRequest: OBWriteDomesticStandingOrderConsent5): OBWriteDomesticStandingOrderConsentResponse6 {
        return buildCreateConsentRequest(consentRequest).sendRequest()
    }

    private fun buildCreateConsentRequest(
        consent: OBWriteDomesticStandingOrderConsent5
    ) = paymentApiClient.newPostRequestBuilder(
        paymentLinks.CreateDomesticStandingOrderConsent,
        tppResource.tpp.getClientCredentialsAccessToken(defaultPaymentScopesForAccessToken),
        consent
    )

    fun createDomesticStandingOrderConsentAndAuthorize(consentRequest: OBWriteDomesticStandingOrderConsent5): Pair<OBWriteDomesticStandingOrderConsentResponse6, AccessToken> {
        val consent = createDomesticStandingOrderConsent(consentRequest)
        val accessTokenAuthorizationCode = PaymentAS().authorizeConsent(
            consent.data.consentId,
            tppResource.tpp.registrationResponse,
            psu,
            tppResource.tpp
        )
        return consent to accessTokenAuthorizationCode
    }

    fun createDomesticStandingOrderConsentAndReject(consentRequest: OBWriteDomesticStandingOrderConsent5): Pair<OBWriteDomesticStandingOrderConsentResponse6, AccessToken> {
        val consent = createDomesticStandingOrderConsent(consentRequest)
        val accessTokenAuthorizationCode = PaymentAS().authorizeConsent(
            consent.data.consentId,
            tppResource.tpp.registrationResponse,
            psu,
            tppResource.tpp,
            "Rejected"
        )
        return consent to accessTokenAuthorizationCode
    }
}