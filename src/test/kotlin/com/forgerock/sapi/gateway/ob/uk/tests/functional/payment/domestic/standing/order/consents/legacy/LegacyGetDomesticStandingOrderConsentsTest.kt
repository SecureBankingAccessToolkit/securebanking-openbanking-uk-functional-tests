package com.forgerock.sapi.gateway.ob.uk.tests.functional.payment.domestic.standing.order.consents.legacy

import assertk.assertThat
import assertk.assertions.isEqualTo
import assertk.assertions.isNotEmpty
import assertk.assertions.isNotNull
import com.forgerock.sapi.gateway.framework.conditions.Status
import com.forgerock.sapi.gateway.framework.extensions.junit.CreateTppCallback
import com.forgerock.sapi.gateway.framework.extensions.junit.EnabledIfVersion
import com.forgerock.sapi.gateway.framework.http.fuel.defaultMapper
import com.forgerock.sapi.gateway.framework.signature.signPayloadSubmitPayment
import com.forgerock.sapi.gateway.ob.uk.support.discovery.payment3_1
import com.forgerock.sapi.gateway.ob.uk.support.discovery.payment3_1_1
import com.forgerock.sapi.gateway.ob.uk.support.discovery.payment3_1_3
import com.forgerock.sapi.gateway.ob.uk.support.discovery.payment3_1_4
import com.forgerock.sapi.gateway.ob.uk.support.payment.PaymentFactory
import com.forgerock.sapi.gateway.ob.uk.support.payment.PaymentRS
import com.forgerock.sapi.gateway.uk.common.shared.api.meta.obie.OBVersion
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import uk.org.openbanking.datamodel.payment.OBWriteDomesticStandingOrderConsentResponse2
import uk.org.openbanking.datamodel.payment.OBWriteDomesticStandingOrderConsentResponse3
import uk.org.openbanking.datamodel.payment.OBWriteDomesticStandingOrderConsentResponse4
import uk.org.openbanking.datamodel.payment.OBWriteDomesticStandingOrderConsentResponse5
import uk.org.openbanking.testsupport.payment.OBWriteDomesticStandingOrderConsentTestDataFactory.*

class LegacyGetDomesticStandingOrderConsentsTest(val tppResource: CreateTppCallback.TppResource) {
    @EnabledIfVersion(
        type = "payments",
        apiVersion = "v3.1.4",
        operations = ["CreateDomesticStandingOrderConsent", "GetDomesticStandingOrderConsent"],
        apis = ["domestic-standing-order-consents"]
    )
    @Test
    fun shouldGetDomesticStandingOrdersConsents_v3_1_4() {
        // Given
        val consentRequest = aValidOBWriteDomesticStandingOrderConsent5()

        val signedPayloadConsent =
            signPayloadSubmitPayment(
                defaultMapper.writeValueAsString(consentRequest),
                tppResource.tpp.signingKey,
                tppResource.tpp.signingKid
            )


        val consent = PaymentRS().consent<OBWriteDomesticStandingOrderConsentResponse5>(
            payment3_1_4.Links.links.CreateDomesticStandingOrderConsent,
            consentRequest,
            tppResource.tpp,
            OBVersion.v3_1_4,
            signedPayloadConsent
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)
        assertThat(consent.risk).isNotNull()

        // When
        val result = PaymentRS().getConsent<OBWriteDomesticStandingOrderConsentResponse5>(
            PaymentFactory.urlWithConsentId(
                payment3_1_4.Links.links.GetDomesticStandingOrderConsent,
                consent.data.consentId
            ),
            tppResource.tpp,
            OBVersion.v3_1_4
        )

        // Then
        assertThat(result).isNotNull()
        assertThat(result.data).isNotNull()
        assertThat(result.risk).isNotNull()
        assertThat(result.data).isEqualTo(consent.data)
        assertThat(result.risk).isEqualTo(consent.risk)
    }

    @EnabledIfVersion(
        type = "payments",
        apiVersion = "v3.1.3",
        operations = ["CreateDomesticStandingOrderConsent", "GetDomesticStandingOrderConsent"],
        apis = ["domestic-standing-order-consents"],
        compatibleVersions = ["v.3.1.2"]
    )
    @Test
    fun shouldGetDomesticStandingOrdersConsents_v3_1_3() {
        // Given
        val consentRequest = aValidOBWriteDomesticStandingOrderConsent4()

        val signedPayloadConsent =
            signPayloadSubmitPayment(
                defaultMapper.writeValueAsString(consentRequest),
                tppResource.tpp.signingKey,
                tppResource.tpp.signingKid,
                true
            )

        val consent = PaymentRS().consent<OBWriteDomesticStandingOrderConsentResponse4>(
            payment3_1_3.Links.links.CreateDomesticStandingOrderConsent,
            consentRequest,
            tppResource.tpp,
            OBVersion.v3_1_3,
            signedPayloadConsent
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)
        assertThat(consent.risk).isNotNull()

        // When
        val result = PaymentRS().getConsent<OBWriteDomesticStandingOrderConsentResponse4>(
            PaymentFactory.urlWithConsentId(
                payment3_1_3.Links.links.GetDomesticStandingOrderConsent,
                consent.data.consentId
            ),
            tppResource.tpp,
            OBVersion.v3_1_3
        )

        // Then
        assertThat(result).isNotNull()
        assertThat(result.data).isNotNull()
        assertThat(result.risk).isNotNull()
        assertThat(result.data).isEqualTo(consent.data)
        assertThat(result.risk).isEqualTo(consent.risk)
    }

    @EnabledIfVersion(
        type = "payments",
        apiVersion = "v3.1.1",
        operations = ["CreateDomesticStandingOrderConsent", "GetDomesticStandingOrderConsent"],
        apis = ["domestic-standing-order-consents"]
    )
    @Test
    fun shouldGetDomesticStandingOrdersConsents_v3_1_1() {
        // Given
        val consentRequest = aValidOBWriteDomesticStandingOrderConsent3()

        val signedPayloadConsent =
            signPayloadSubmitPayment(
                defaultMapper.writeValueAsString(consentRequest),
                tppResource.tpp.signingKey,
                tppResource.tpp.signingKid,
                true
            )

        val consent = PaymentRS().consent<OBWriteDomesticStandingOrderConsentResponse3>(
            payment3_1_1.Links.links.CreateDomesticStandingOrderConsent,
            consentRequest,
            tppResource.tpp,
            OBVersion.v3_1_1,
            signedPayloadConsent
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)
        assertThat(consent.risk).isNotNull()

        // When
        val result = PaymentRS().getConsent<OBWriteDomesticStandingOrderConsentResponse3>(
            PaymentFactory.urlWithConsentId(
                payment3_1_1.Links.links.GetDomesticStandingOrderConsent,
                consent.data.consentId
            ),
            tppResource.tpp,
            OBVersion.v3_1_1
        )

        // Then
        assertThat(result).isNotNull()
        assertThat(result.data).isNotNull()
        assertThat(result.risk).isNotNull()
        assertThat(result.data).isEqualTo(consent.data)
        assertThat(result.risk).isEqualTo(consent.risk)
    }

    @EnabledIfVersion(
        type = "payments",
        apiVersion = "v3.1",
        operations = ["CreateDomesticStandingOrderConsent", "GetDomesticStandingOrderConsent"],
        apis = ["domestic-standing-order-consents"]
    )
    @Test
    fun shouldGetDomesticStandingOrdersConsents_v3_1() {
        // Given
        val consentRequest = aValidOBWriteDomesticStandingOrderConsent2()

        val signedPayloadConsent =
            signPayloadSubmitPayment(
                defaultMapper.writeValueAsString(consentRequest),
                tppResource.tpp.signingKey,
                tppResource.tpp.signingKid,
                true
            )

        val consent = PaymentRS().consent<OBWriteDomesticStandingOrderConsentResponse2>(
            payment3_1.Links.links.CreateDomesticStandingOrderConsent,
            consentRequest,
            tppResource.tpp,
            OBVersion.v3_1,
            signedPayloadConsent
        )

        assertThat(consent).isNotNull()
        assertThat(consent.data).isNotNull()
        assertThat(consent.data.consentId).isNotEmpty()
        Assertions.assertThat(consent.data.status.toString()).`is`(Status.consentCondition)
        assertThat(consent.risk).isNotNull()

        // When
        val result = PaymentRS().getConsent<OBWriteDomesticStandingOrderConsentResponse2>(
            PaymentFactory.urlWithConsentId(
                payment3_1.Links.links.GetDomesticStandingOrderConsent,
                consent.data.consentId
            ),
            tppResource.tpp,
            OBVersion.v3_1
        )

        // Then
        assertThat(result).isNotNull()
        assertThat(result.data).isNotNull()
        assertThat(result.risk).isNotNull()
        assertThat(result.data).isEqualTo(consent.data)
        assertThat(result.risk).isEqualTo(consent.risk)
    }
}