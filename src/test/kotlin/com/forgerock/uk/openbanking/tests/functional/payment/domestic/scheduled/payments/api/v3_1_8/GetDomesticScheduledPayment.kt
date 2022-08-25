package com.forgerock.uk.openbanking.tests.functional.payment.domestic.scheduled.payments.api.v3_1_8

import assertk.assertThat
import assertk.assertions.isEqualTo
import assertk.assertions.isNotEmpty
import assertk.assertions.isNotNull
import com.forgerock.securebanking.framework.conditions.Status
import com.forgerock.securebanking.framework.extensions.junit.CreateTppCallback
import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion
import com.forgerock.uk.openbanking.support.discovery.getPaymentsApiLinks
import com.forgerock.uk.openbanking.support.payment.PaymentFactory
import com.forgerock.uk.openbanking.support.payment.defaultPaymentScopesForAccessToken
import com.forgerock.uk.openbanking.tests.functional.payment.domestic.scheduled.payments.consents.api.v3_1_8.CreateDomesticScheduledPaymentsConsents
import org.assertj.core.api.Assertions
import uk.org.openbanking.datamodel.payment.*
import uk.org.openbanking.testsupport.payment.OBWriteDomesticScheduledConsentTestDataFactory

class GetDomesticScheduledPayment(val version: OBVersion, val tppResource: CreateTppCallback.TppResource) {

    private val createDomesticScheduledPaymentsConsents = CreateDomesticScheduledPaymentsConsents(version, tppResource)
    private val createDomesticScheduledPayment = CreateDomesticScheduledPayment(version, tppResource)
    private val paymentLinks = getPaymentsApiLinks(version)
    private val paymentApiClient = tppResource.tpp.paymentApiClient

    fun getDomesticScheduledPaymentsTest() {
        // Given
        val consentRequest = OBWriteDomesticScheduledConsentTestDataFactory.aValidOBWriteDomesticScheduledConsent4()
        val paymentResponse = createDomesticScheduledPayment.submitPayment(consentRequest)

        // When
        val getPaymentResponse = getDomesticScheduledPayment(paymentResponse)

        // Then
        assertThat(getPaymentResponse).isNotNull()
        assertThat(getPaymentResponse.data.domesticScheduledPaymentId).isNotEmpty()
        assertThat(getPaymentResponse.data.creationDateTime).isNotNull()
        Assertions.assertThat(getPaymentResponse.data.status.toString()).`is`(Status.paymentCondition)
    }

    fun shouldGetDomesticScheduledPayments_withReadRefundTest() {
        // Given
        val consentRequest = OBWriteDomesticScheduledConsentTestDataFactory.aValidOBWriteDomesticScheduledConsent4()
        consentRequest.data.readRefundAccount = OBReadRefundAccountEnum.YES
        val (consent, accessTokenAuthorizationCode) = createDomesticScheduledPaymentsConsents.createDomesticScheduledPaymentConsentAndAuthorize(
            consentRequest
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        assertThat(consent.data.readRefundAccount).isEqualTo(OBReadRefundAccountEnum.YES)
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)

        val paymentResponse = createDomesticScheduledPayment.submitPayment(consentRequest)

        val getPaymentResponse = getDomesticScheduledPayment(paymentResponse)
        // Then
        assertThat(getPaymentResponse).isNotNull()
        assertThat(getPaymentResponse.data.domesticScheduledPaymentId).isNotEmpty()
        assertThat(getPaymentResponse.data.creationDateTime).isNotNull()
        //TODO: Waiting for the fix from the issue: https://github.com/SecureBankingAccessToolkit/SecureBankingAccessToolkit/issues/241
//        assertThat(paymentResult.data.refund.account.identification).isEqualTo(consent.data.initiation.debtorAccount.identification)
        Assertions.assertThat(getPaymentResponse.data.status.toString()).`is`(Status.paymentCondition)
    }

    private fun getDomesticScheduledPayment(paymentResponse: OBWriteDomesticScheduledResponse5): OBWriteDomesticScheduledResponse5 {
        val getDomesticPaymentUrl = PaymentFactory.urlWithDomesticScheduledPaymentId(
            paymentLinks.GetDomesticScheduledPayment,
            paymentResponse.data.domesticScheduledPaymentId
        )
        return paymentApiClient.sendGetRequest(
            getDomesticPaymentUrl,
            tppResource.tpp.getClientCredentialsAccessToken(defaultPaymentScopesForAccessToken)
        )
    }
}