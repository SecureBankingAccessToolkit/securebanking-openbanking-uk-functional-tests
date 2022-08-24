package com.forgerock.uk.openbanking.tests.functional.payment.domestic.standing.order.api.v3_1_8

import assertk.assertThat
import assertk.assertions.isEqualTo
import assertk.assertions.isNotEmpty
import assertk.assertions.isNotNull
import com.forgerock.securebanking.framework.conditions.Status
import com.forgerock.securebanking.framework.extensions.junit.CreateTppCallback
import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion
import com.forgerock.uk.openbanking.support.payment.PaymentFactory
import com.forgerock.uk.openbanking.support.payment.defaultPaymentScopesForAccessToken
import com.forgerock.uk.openbanking.tests.functional.payment.domestic.standing.order.consents.api.v3_1_8.CreateDomesticStandingOrderConsents
import org.assertj.core.api.Assertions
import uk.org.openbanking.datamodel.payment.*
import uk.org.openbanking.testsupport.payment.OBWriteDomesticStandingOrderConsentTestDataFactory

class GetDomesticStandingOrder(val version: OBVersion, val tppResource: CreateTppCallback.TppResource) {

    private val createDomesticStandingOrderConsentsApi = CreateDomesticStandingOrderConsents(version, tppResource)
    private val createDomesticStandingOrderApi = CreateDomesticStandingOrder(version, tppResource)
    private val paymentApiClient = tppResource.tpp.paymentApiClient

    fun getDomesticStandingOrdersTest() {
        // Given
        val consentRequest =
            OBWriteDomesticStandingOrderConsentTestDataFactory.aValidOBWriteDomesticStandingOrderConsent5()
        val standingOrderResponse = createDomesticStandingOrderApi.submitStandingOrder(consentRequest)

        // When
        val getStandingOrderResponse = getStandingOrder(standingOrderResponse)

        // Then
        assertThat(getStandingOrderResponse).isNotNull()
        assertThat(getStandingOrderResponse.data.domesticStandingOrderId).isNotEmpty()
        assertThat(getStandingOrderResponse.data.creationDateTime).isNotNull()
        Assertions.assertThat(getStandingOrderResponse.data.status.toString()).`is`(Status.paymentCondition)
    }

    fun getDomesticStandingOrders_mandatoryFieldsTest() {
        // Given
        val consentRequest =
            OBWriteDomesticStandingOrderConsentTestDataFactory.aValidOBWriteDomesticStandingOrderConsent5MandatoryFields()
        val standingOrderResponse = createDomesticStandingOrderApi.submitStandingOrder(consentRequest)

        // When
        val getStandingOrderResponse = getStandingOrder(standingOrderResponse)

        // Then
        assertThat(getStandingOrderResponse).isNotNull()
        assertThat(getStandingOrderResponse.data.domesticStandingOrderId).isNotEmpty()
        assertThat(getStandingOrderResponse.data.creationDateTime).isNotNull()
        Assertions.assertThat(getStandingOrderResponse.data.status.toString()).`is`(Status.paymentCondition)
    }

    fun shouldGetDomesticStandingOrders_withReadRefundTest() {
        // Given
        val consentRequest =
            OBWriteDomesticStandingOrderConsentTestDataFactory.aValidOBWriteDomesticStandingOrderConsent5()
        consentRequest.data.readRefundAccount = OBReadRefundAccountEnum.YES
        val (consent, accessTokenAuthorizationCode) = createDomesticStandingOrderConsentsApi.createDomesticStandingOrderConsentAndAuthorize(
            consentRequest
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        assertThat(consent.data.readRefundAccount).isEqualTo(OBReadRefundAccountEnum.YES)
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)

        val standingOrderResponse = createDomesticStandingOrderApi.submitStandingOrder(consent, accessTokenAuthorizationCode)

        // When
        val getStandingOrderResponse = getStandingOrder(standingOrderResponse)

        // Then
        assertThat(getStandingOrderResponse).isNotNull()
        assertThat(getStandingOrderResponse.data.domesticStandingOrderId).isNotEmpty()
        assertThat(getStandingOrderResponse.data.creationDateTime).isNotNull()
        //TODO: Waiting for the fix from the issue: https://github.com/SecureBankingAccessToolkit/SecureBankingAccessToolkit/issues/241
//        assertThat(result.data.refund.account.identification).isEqualTo(consent.data.initiation.debtorAccount.identification)
        Assertions.assertThat(getStandingOrderResponse.data.status.toString()).`is`(Status.paymentCondition)
    }

    private fun getStandingOrder(standingOrderResponse: OBWriteDomesticStandingOrderResponse6): OBWriteDomesticStandingOrderResponse6 {
        val getDomesticPaymentUrl = PaymentFactory.urlWithDomesticStandingOrderId(
            createDomesticStandingOrderConsentsApi.paymentLinks.GetDomesticStandingOrder,
            standingOrderResponse.data.domesticStandingOrderId
        )
        return paymentApiClient.sendGetRequest(
            getDomesticPaymentUrl,
            tppResource.tpp.getClientCredentialsAccessToken(defaultPaymentScopesForAccessToken)
        )
    }
}