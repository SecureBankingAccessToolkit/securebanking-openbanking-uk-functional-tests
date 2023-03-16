package com.forgerock.sapi.gateway.ob.uk.tests.functional.account.standing.orders.legacy

import assertk.assertThat
import assertk.assertions.isNotEmpty
import assertk.assertions.isNotNull
import com.forgerock.sapi.gateway.framework.configuration.USER_ACCOUNT_ID
import com.forgerock.sapi.gateway.framework.configuration.psu
import com.forgerock.sapi.gateway.framework.extensions.junit.CreateTppCallback
import com.forgerock.sapi.gateway.framework.extensions.junit.EnabledIfVersion
import com.forgerock.sapi.gateway.ob.uk.support.account.AccountAS
import com.forgerock.sapi.gateway.ob.uk.support.account.AccountFactory.Companion.urlWithAccountId
import com.forgerock.sapi.gateway.ob.uk.support.account.AccountRS
import com.forgerock.sapi.gateway.ob.uk.support.discovery.accountAndTransaction3_1
import com.forgerock.sapi.gateway.ob.uk.support.discovery.accountAndTransaction3_1_2
import com.forgerock.sapi.gateway.ob.uk.support.discovery.accountAndTransaction3_1_4
import org.junit.jupiter.api.Test
import uk.org.openbanking.datamodel.account.*
import uk.org.openbanking.datamodel.account.OBExternalPermissions1Code.READACCOUNTSDETAIL

class LegacyGetAccountStandingOrdersTest(val tppResource: CreateTppCallback.TppResource) {

    @EnabledIfVersion(
        type = "accounts",
        apiVersion = "v3.1",
        operations = ["CreateAccountAccessConsent", "GetAccounts", "GetAccountStandingOrders"],
        apis = ["standing-orders"],
        compatibleVersions = ["v.3.0"]
    )
    @Test
    fun shouldGetAccountStandingOrders_v3_1() {
        // Given
        val consentRequest = OBReadConsent1().data(
            OBReadData1()
                .permissions(listOf(READACCOUNTSDETAIL, OBExternalPermissions1Code.READSTANDINGORDERSDETAIL))
        )
            .risk(OBRisk2())
        val consent = AccountRS().consent<OBReadConsentResponse1>(
            accountAndTransaction3_1.Links.links.CreateAccountAccessConsent,
            consentRequest,
            tppResource.tpp
        )
        val accessToken = AccountAS().getAccessToken(
            consent.data.consentId,
            tppResource.tpp.registrationResponse,
            psu,
            tppResource.tpp
        )

        // When
        val result = AccountRS().getAccountsData<OBReadStandingOrder4>(
            urlWithAccountId(
                accountAndTransaction3_1.Links.links.GetAccountStandingOrders,
                USER_ACCOUNT_ID
            ), accessToken
        )

        // Then
        assertThat(result).isNotNull()
        assertThat(result.data.standingOrder).isNotEmpty()
    }

    @EnabledIfVersion(
        type = "accounts",
        apiVersion = "v3.1.2",
        operations = ["CreateAccountAccessConsent", "GetAccounts", "GetAccountStandingOrders"],
        apis = ["standing-orders"],
        compatibleVersions = ["v.3.1.1"]
    )
    @Test
    fun shouldGetAccountStandingOrders_v3_1_2() {
        // Given
        val consentRequest = OBReadConsent1().data(
            OBReadData1()
                .permissions(listOf(READACCOUNTSDETAIL, OBExternalPermissions1Code.READSTANDINGORDERSDETAIL))
        )
            .risk(OBRisk2())
        val consent = AccountRS().consent<OBReadConsentResponse1>(
            accountAndTransaction3_1_2.Links.links.CreateAccountAccessConsent,
            consentRequest,
            tppResource.tpp
        )
        val accessToken = AccountAS().getAccessToken(
            consent.data.consentId,
            tppResource.tpp.registrationResponse,
            psu,
            tppResource.tpp
        )

        // When
        val result = AccountRS().getAccountsData<OBReadStandingOrder5>(
            urlWithAccountId(
                accountAndTransaction3_1_2.Links.links.GetAccountStandingOrders,
                USER_ACCOUNT_ID
            ), accessToken
        )

        // Then
        assertThat(result).isNotNull()
        assertThat(result.data.standingOrder).isNotEmpty()
    }

    @EnabledIfVersion(
        type = "accounts",
        apiVersion = "v3.1.4",
        operations = ["CreateAccountAccessConsent", "GetAccounts", "GetAccountStandingOrders"],
        apis = ["standing-orders"],
        compatibleVersions = ["v.3.1.3"]
    )
    @Test
    fun shouldGetAccountStandingOrders_v3_1_4() {
        // Given
        val consentRequest = OBReadConsent1().data(
            OBReadData1()
                .permissions(listOf(READACCOUNTSDETAIL, OBExternalPermissions1Code.READSTANDINGORDERSDETAIL))
        )
            .risk(OBRisk2())
        val consent = AccountRS().consent<OBReadConsentResponse1>(
            accountAndTransaction3_1_4.Links.links.CreateAccountAccessConsent,
            consentRequest,
            tppResource.tpp
        )
        val accessToken = AccountAS().getAccessToken(
            consent.data.consentId,
            tppResource.tpp.registrationResponse,
            psu,
            tppResource.tpp
        )

        // When
        val result = AccountRS().getAccountsData<OBReadStandingOrder6>(
            urlWithAccountId(
                accountAndTransaction3_1_4.Links.links.GetAccountStandingOrders,
                USER_ACCOUNT_ID
            ), accessToken
        )

        // Then
        assertThat(result).isNotNull()
        assertThat(result.data.standingOrder).isNotEmpty()
    }
}