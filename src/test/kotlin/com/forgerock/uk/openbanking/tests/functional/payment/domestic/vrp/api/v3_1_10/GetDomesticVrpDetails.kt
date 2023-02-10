package com.forgerock.uk.openbanking.tests.functional.payment.domestic.vrp.api.v3_1_10

import assertk.assertThat
import assertk.assertions.isNotEqualTo
import assertk.assertions.isNotNull
import com.forgerock.securebanking.framework.extensions.junit.CreateTppCallback
import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion
import com.forgerock.uk.openbanking.support.discovery.getPaymentsApiLinks
import com.forgerock.uk.openbanking.support.payment.PaymentFactory
import com.forgerock.uk.openbanking.support.payment.defaultPaymentScopesForAccessToken
import uk.org.openbanking.datamodel.payment.OBWritePaymentDetailsResponse1
import uk.org.openbanking.datamodel.vrp.OBDomesticVRPResponse
import uk.org.openbanking.testsupport.vrp.OBDomesticVrpConsentRequestTestDataFactory

class GetDomesticVrpDetails(
    val version: OBVersion,
    val tppResource: CreateTppCallback.TppResource
) {
    private val createDomesticVrpApi = CreateDomesticVrp(version, tppResource)
    private val paymentLinks = getPaymentsApiLinks(version)
    private val paymentApiClient = tppResource.tpp.paymentApiClient

    fun getDomesticVrpDetailsTest() {
        // Given
        val consentRequest = OBDomesticVrpConsentRequestTestDataFactory.aValidOBDomesticVRPConsentRequest()
        val result = createDomesticVrpApi.submitPayment(consentRequest)

        // When
        val domesticVrpDetails = getDomesticVrpDetails(result)

        // Then
        assertThat(domesticVrpDetails).isNotNull()
        assertThat(domesticVrpDetails.data).isNotNull()
        assertThat(domesticVrpDetails.data.paymentStatus).isNotNull()
    }

    fun getDomesticVrpDetailsWithMultiplePaymentsTest() {
        // Given
        val consentRequest = OBDomesticVrpConsentRequestTestDataFactory.aValidOBDomesticVRPConsentRequest()
        val payment1 = createDomesticVrpApi.submitPayment(consentRequest)
        val payment2 = createDomesticVrpApi.submitPayment(consentRequest)

        assertThat(payment1.data.domesticVRPId).isNotEqualTo(payment2.data.domesticVRPId)

        // When
        val domesticVrpDetails1 = getDomesticVrpDetails(payment1)
        val domesticVrpDetails2 = getDomesticVrpDetails(payment2)

        // Then
        assertThat(domesticVrpDetails1).isNotNull()
        assertThat(domesticVrpDetails1.data).isNotNull()
        assertThat(domesticVrpDetails1.data.paymentStatus).isNotNull()

        assertThat(domesticVrpDetails2).isNotNull()
        assertThat(domesticVrpDetails2.data).isNotNull()
        assertThat(domesticVrpDetails2.data.paymentStatus).isNotNull()
    }

    fun getDomesticVrpDetails_mandatoryFieldsTest() {
        // Given
        val consentRequest = OBDomesticVrpConsentRequestTestDataFactory.aValidOBDomesticVRPConsentRequest()
        val result = createDomesticVrpApi.submitPayment(consentRequest)

        // When
        val domesticVrpDetails = getDomesticVrpDetails(result)

        // Then
        assertThat(domesticVrpDetails).isNotNull()
        assertThat(domesticVrpDetails.data).isNotNull()
        assertThat(domesticVrpDetails.data.paymentStatus).isNotNull()
    }

    private fun getDomesticVrpDetails(domesticVrpResponse: OBDomesticVRPResponse): OBWritePaymentDetailsResponse1 {
        val getDomesticVrpDetailsUrl = PaymentFactory.urlWithDomesticVrpPaymentId(
            paymentLinks.GetDomesticVrpPaymentDetails,
            domesticVrpResponse.data.domesticVRPId
        )
        return paymentApiClient.sendGetRequest(
            getDomesticVrpDetailsUrl,
            tppResource.tpp.getClientCredentialsAccessToken(defaultPaymentScopesForAccessToken)
        )
    }
}