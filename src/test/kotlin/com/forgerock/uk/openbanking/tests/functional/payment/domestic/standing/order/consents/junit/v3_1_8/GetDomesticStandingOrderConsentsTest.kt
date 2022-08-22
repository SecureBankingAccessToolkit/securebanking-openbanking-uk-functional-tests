package com.forgerock.uk.openbanking.tests.functional.payment.domestic.standing.order.consents.junit.v3_1_8

import com.forgerock.securebanking.framework.extensions.junit.CreateTppCallback
import com.forgerock.securebanking.framework.extensions.junit.EnabledIfVersion
import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion
import com.forgerock.uk.openbanking.tests.functional.payment.domestic.standing.order.consents.api.v3_1_8.GetDomesticStandingOrderConsents
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class GetDomesticStandingOrderConsentsTest(val tppResource: CreateTppCallback.TppResource) {

    lateinit var getDomesticStandingOrderConsents: GetDomesticStandingOrderConsents

    @BeforeEach
    fun setUp() {
        getDomesticStandingOrderConsents = GetDomesticStandingOrderConsents(OBVersion.v3_1_8, tppResource)
    }

    @EnabledIfVersion(
        type = "payments",
        apiVersion = "v3.1.8",
        operations = ["CreateDomesticStandingOrder", "CreateDomesticStandingOrderConsent", "GetDomesticStandingOrderConsent"],
        apis = ["domestic-standing-orders", "domestic-standing-order-consents"],
        compatibleVersions = ["v.3.1.7", "v.3.1.6", "v.3.1.5"]
    )
    @Test
    fun createDomesticStandingOrder_v3_1_8() {
        getDomesticStandingOrderConsents.shouldGetDomesticStandingOrdersConsents_v3_1_8()
    }

}