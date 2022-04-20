package com.forgerock.securebanking.tests.functional.account.parties

import assertk.assertThat
import assertk.assertions.isNotEmpty
import assertk.assertions.isNotEqualTo
import assertk.assertions.isNotNull
import com.forgerock.securebanking.framework.configuration.psu
import com.forgerock.securebanking.framework.extensions.junit.CreateTppCallback
import com.forgerock.securebanking.framework.extensions.junit.EnabledIfVersion
import com.forgerock.securebanking.support.account.AccountAS
import com.forgerock.securebanking.support.account.AccountFactory.Companion.urlWithAccountId
import com.forgerock.securebanking.support.account.AccountRS
import com.forgerock.securebanking.support.discovery.accountAndTransaction3_1
import com.forgerock.securebanking.support.discovery.accountAndTransaction3_1_2
import com.forgerock.securebanking.support.discovery.accountAndTransaction3_1_8
import org.junit.jupiter.api.Test
import uk.org.openbanking.datamodel.account.*
import uk.org.openbanking.datamodel.account.OBExternalPermissions1Code.READACCOUNTSDETAIL
import uk.org.openbanking.datamodel.account.OBExternalPermissions1Code.READPARTY

class GetAccountPartyTest(val tppResource: CreateTppCallback.TppResource) {
    @EnabledIfVersion(
        type = "accounts",
        apiVersion = "v3.1",
        operations = ["CreateAccountAccessConsent", "GetAccounts", "GetAccountParty"],
        apis = ["party"],
        compatibleVersions = ["v.3.0"]
    )
    @Test
    fun shouldGetAccountParty_v3_1() {
        // Given
        val consentRequest = OBReadConsent1().data(
            OBReadData1()
                .permissions(listOf(READPARTY, READACCOUNTSDETAIL))
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
        val (accountId, psuId) = AccountRS().getFirstAccountIdAndPsuId(
            accountAndTransaction3_1.Links.links.GetAccounts,
            accessToken
        )
        assertThat(accountId).isNotEqualTo("")
        assertThat(psuId).isNotEqualTo("")
        psu.user.uid = psuId

        // When
        val result = AccountRS().getAccountsDataEndUser<OBReadParty1>(
            urlWithAccountId(
                accountAndTransaction3_1.Links.links.GetAccountParty,
                accountId
            ), accessToken
        )

        // Then
        assertThat(result).isNotNull()
        assertThat(result.data.party.partyId).isNotEmpty()
    }


    @EnabledIfVersion(
        type = "accounts",
        apiVersion = "v3.1.2",
        operations = ["CreateAccountAccessConsent", "GetAccounts", "GetAccountParty"],
        apis = ["party"],
        compatibleVersions = ["v.3.1.1"]
    )
    @Test
    fun shouldGetAccountParty_v3_1_2() {
        // Given
        val consentRequest = OBReadConsent1().data(
            OBReadData1()
                .permissions(listOf(READPARTY, READACCOUNTSDETAIL))
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
        val (accountId, psuId) = AccountRS().getFirstAccountIdAndPsuId(
            accountAndTransaction3_1_2.Links.links.GetAccounts,
            accessToken
        )
        assertThat(accountId).isNotEqualTo("")
        assertThat(psuId).isNotEqualTo("")
        psu.user.uid = psuId

        // When
        val result = AccountRS().getAccountsData<OBReadParty2>(
            urlWithAccountId(
                accountAndTransaction3_1_2.Links.links.GetAccountParty,
                accountId
            ), accessToken
        )

        // Then
        assertThat(result).isNotNull()
        assertThat(result.data.party.partyId).isNotEmpty()
    }

    @EnabledIfVersion(
        type = "accounts",
        apiVersion = "v3.1.8",
        operations = ["CreateAccountAccessConsent", "GetAccounts", "GetAccountParty"],
        apis = ["party"],
        compatibleVersions = ["v.3.1.7", "v.3.1.6", "v.3.1.5", "v.3.1.4", "v.3.1.3"]
    )
    @Test
    fun shouldGetAccountParty_v3_1_8() {
        // Given
        val consentRequest = OBReadConsent1().data(
            OBReadData1()
                .permissions(listOf(READPARTY, READACCOUNTSDETAIL))
        )
            .risk(OBRisk2())
        val consent = AccountRS().consent<OBReadConsentResponse1>(
            accountAndTransaction3_1_8.Links.links.CreateAccountAccessConsent,
            consentRequest,
            tppResource.tpp
        )
        val accessToken = AccountAS().getAccessToken(
            consent.data.consentId,
            tppResource.tpp.registrationResponse,
            psu,
            tppResource.tpp
        )
        val (accountId, psuId) = AccountRS().getFirstAccountIdAndPsuId(
            accountAndTransaction3_1_8.Links.links.GetAccounts,
            accessToken
        )
        assertThat(accountId).isNotEqualTo("")
        assertThat(psuId).isNotEqualTo("")
        psu.user.uid = psuId

        // When
        val result = AccountRS().getAccountsDataEndUser<OBReadParty2>(
            urlWithAccountId(
                accountAndTransaction3_1_8.Links.links.GetAccountParty,
                accountId
            ), accessToken
        )

        // Then
        assertThat(result).isNotNull()
        assertThat(result.data.party.partyId).isNotEmpty()
    }
}