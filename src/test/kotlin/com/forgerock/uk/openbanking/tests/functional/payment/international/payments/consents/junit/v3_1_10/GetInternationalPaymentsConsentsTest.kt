package com.forgerock.uk.openbanking.tests.functional.payment.international.payments.consents.junit.v3_1_10

import com.forgerock.securebanking.framework.extensions.junit.CreateTppCallback
import com.forgerock.securebanking.framework.extensions.junit.EnabledIfVersion
import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion
import com.forgerock.uk.openbanking.tests.functional.payment.international.payments.consents.api.v3_1_8.GetInternationalPaymentsConsents
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class GetInternationalPaymentsConsentsTest(val tppResource: CreateTppCallback.TppResource) {

    lateinit var getInternationalPaymentsConsents: GetInternationalPaymentsConsents

    @BeforeEach
    fun setUp() {
        getInternationalPaymentsConsents = GetInternationalPaymentsConsents(OBVersion.v3_1_10, tppResource)
    }

    @EnabledIfVersion(
        type = "payments",
        apiVersion = "v3.1.10",
        operations = ["CreateInternationalPaymentConsent", "GetInternationalPaymentConsent"],
        apis = ["international-payment-consents"]
    )
    @Test
    fun shouldGetInternationalPaymentsConsents_rateType_AGREED_v3_1_10() {
        getInternationalPaymentsConsents.shouldGetInternationalPaymentsConsents_rateType_AGREED_Test()
    }

    @EnabledIfVersion(
        type = "payments",
        apiVersion = "v3.1.10",
        operations = ["CreateInternationalPaymentConsent", "GetInternationalPaymentConsent"],
        apis = ["international-payment-consents"]
    )
    @Test
    fun shouldGetInternationalPaymentsConsents_rateType_ACTUAL_v3_1_10() {
        getInternationalPaymentsConsents.shouldGetInternationalPaymentsConsents_rateType_ACTUAL_Test()
    }

    @EnabledIfVersion(
        type = "payments",
        apiVersion = "v3.1.10",
        operations = ["CreateInternationalPaymentConsent", "GetInternationalPaymentConsent"],
        apis = ["international-payment-consents"]
    )
    @Test
    fun shouldGetInternationalPaymentsConsents_rateType_INDICATIVE_v3_1_10() {
        getInternationalPaymentsConsents.shouldGetInternationalPaymentsConsents_rateType_INDICATIVE_Test()
    }
}