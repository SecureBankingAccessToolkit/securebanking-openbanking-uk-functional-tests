package com.forgerock.uk.openbanking.tests.functional.payment.domestic.scheduled.payments.consents.junit.v3_1_8

import com.forgerock.securebanking.framework.extensions.junit.CreateTppCallback
import com.forgerock.securebanking.framework.extensions.junit.EnabledIfVersion
import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion
import com.forgerock.uk.openbanking.tests.functional.payment.domestic.scheduled.payments.consents.api.v3_1_8.CreateDomesticScheduledPaymentsConsents
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class CreateDomesticScheduledPaymentsConsentsTest(val tppResource: CreateTppCallback.TppResource) {

    lateinit var createDomesticScheduledPaymentsConsentsApi: CreateDomesticScheduledPaymentsConsents

    @BeforeEach
    fun setUp() {
        createDomesticScheduledPaymentsConsentsApi =
            CreateDomesticScheduledPaymentsConsents(OBVersion.v3_1_8, tppResource)
    }

    @EnabledIfVersion(
        type = "payments",
        apiVersion = "v3.1.8",
        operations = ["CreateDomesticScheduledPaymentConsent"],
        apis = ["domestic-scheduled-payment-consents"],
        compatibleVersions = ["v.3.1.7", "v.3.1.6", "v.3.1.5"]
    )
    @Test
    fun createDomesticScheduledPaymentsConsents_v3_1_8() {
        createDomesticScheduledPaymentsConsentsApi.createDomesticScheduledPaymentsConsentsTest()
    }

    @EnabledIfVersion(
        type = "payments",
        apiVersion = "v3.1.8",
        operations = ["CreateDomesticScheduledPaymentConsent"],
        apis = ["domestic-scheduled-payment-consents"],
        compatibleVersions = ["v.3.1.7", "v.3.1.6", "v.3.1.5"]
    )
    @Test
    fun createDomesticScheduledPaymentsConsents_withDebtorAccount_v3_1_8() {
        createDomesticScheduledPaymentsConsentsApi.createDomesticScheduledPaymentsConsents_withDebtorAccountTest()
    }

    @EnabledIfVersion(
        type = "payments",
        apiVersion = "v3.1.8",
        operations = ["CreateDomesticScheduledPaymentConsent"],
        apis = ["domestic-scheduled-payment-consents"],
        compatibleVersions = ["v.3.1.7", "v.3.1.6", "v.3.1.5"]
    )
    @Test
    fun createDomesticScheduledPaymentsConsents_NoIdempotencyKey_throwsBadRequestTest_v3_1_8() {
        createDomesticScheduledPaymentsConsentsApi.createDomesticScheduledPaymentsConsents_NoIdempotencyKey_throwsBadRequestTest()
    }

    @EnabledIfVersion(
        type = "payments",
        apiVersion = "v3.1.8",
        operations = ["CreateDomesticScheduledPaymentConsent"],
        apis = ["domestic-scheduled-payment-consents"],
        compatibleVersions = ["v.3.1.7", "v.3.1.6", "v.3.1.5"]
    )
    @Test
    fun createDomesticScheduledPaymentsConsents_throwsInvalidDebtorAccount_v3_1_8() {
        createDomesticScheduledPaymentsConsentsApi.createDomesticScheduledPaymentsConsents_throwsInvalidDebtorAccountTest()
    }

    @EnabledIfVersion(
        type = "payments",
        apiVersion = "v3.1.8",
        operations = ["CreateDomesticScheduledPaymentConsent"],
        apis = ["domestic-scheduled-payment-consents"],
        compatibleVersions = ["v.3.1.7", "v.3.1.6", "v.3.1.5"]
    )
    @Test
    fun shouldCreateDomesticScheduledPaymentsConsents_throwsSendInvalidFormatDetachedJws_v3_1_8() {
        createDomesticScheduledPaymentsConsentsApi.shouldCreateDomesticScheduledPaymentsConsents_throwsSendInvalidFormatDetachedJwsTest()
    }

    @EnabledIfVersion(
        type = "payments",
        apiVersion = "v3.1.8",
        operations = ["CreateDomesticScheduledPaymentConsent"],
        apis = ["domestic-scheduled-payment-consents"],
        compatibleVersions = ["v.3.1.7", "v.3.1.6", "v.3.1.5"]
    )
    @Test
    fun shouldCreateDomesticScheduledPaymentsConsents_throwsNoDetachedJws_v3_1_8() {
        createDomesticScheduledPaymentsConsentsApi.shouldCreateDomesticScheduledPaymentsConsents_throwsNoDetachedJwsTest()
    }

    @EnabledIfVersion(
        type = "payments",
        apiVersion = "v3.1.8",
        operations = ["CreateDomesticScheduledPaymentConsent"],
        apis = ["domestic-scheduled-payment-consents"],
        compatibleVersions = ["v.3.1.7", "v.3.1.6", "v.3.1.5"]
    )
    @Test
    fun shouldCreateDomesticScheduledPaymentsConsents_throwsNotPermittedB64HeaderAddedInTheDetachedJws_v3_1_8() {
        createDomesticScheduledPaymentsConsentsApi.shouldCreateDomesticScheduledPaymentsConsents_throwsNotPermittedB64HeaderAddedInTheDetachedJwsTest()
    }

    @EnabledIfVersion(
        type = "payments",
        apiVersion = "v3.1.8",
        operations = ["CreateDomesticScheduledPaymentConsent"],
        apis = ["domestic-scheduled-payment-consents"],
        compatibleVersions = ["v.3.1.7", "v.3.1.6", "v.3.1.5"]
    )
    @Test
    fun shouldCreateDomesticScheduledPaymentsConsents_throwsSendInvalidKidDetachedJws_v3_1_8() {
        createDomesticScheduledPaymentsConsentsApi.shouldCreateDomesticScheduledPaymentsConsents_throwsSendInvalidKidDetachedJwsTest()
    }

    @EnabledIfVersion(
        type = "payments",
        apiVersion = "v3.1.8",
        operations = ["CreateDomesticScheduledPaymentConsent"],
        apis = ["domestic-scheduled-payment-consents"],
        compatibleVersions = ["v.3.1.7", "v.3.1.6", "v.3.1.5"]
    )
    @Test
    fun shouldCreateDomesticScheduledPaymentsConsents_throwsRequestExecutionTimeInThePast_v3_1_8() {
        createDomesticScheduledPaymentsConsentsApi.shouldCreateDomesticScheduledPaymentsConsents_throwsRequestExecutionTimeInThePastTest()
    }

    @EnabledIfVersion(
        type = "payments",
        apiVersion = "v3.1.8",
        operations = ["CreateDomesticScheduledPaymentConsent"],
        apis = ["domestic-scheduled-payment-consents"],
        compatibleVersions = ["v.3.1.7", "v.3.1.6", "v.3.1.5"]
    )
    @Test
    fun shouldCreateDomesticScheduledPaymentsConsents_throwsRejectedConsent_v3_1_8() {
        createDomesticScheduledPaymentsConsentsApi.shouldCreateDomesticScheduledPaymentsConsents_throwsRejectedConsentTest()
    }
}