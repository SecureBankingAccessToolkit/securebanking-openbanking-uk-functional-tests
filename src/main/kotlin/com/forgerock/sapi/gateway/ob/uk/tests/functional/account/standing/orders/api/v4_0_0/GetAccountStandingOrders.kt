package com.forgerock.sapi.gateway.ob.uk.tests.functional.account.standing.orders.api.v4_0_0

import assertk.assertThat
import assertk.assertions.isNotEmpty
import assertk.assertions.isNotNull
import com.forgerock.sapi.gateway.framework.configuration.USER_ACCOUNT_ID
import com.forgerock.sapi.gateway.framework.extensions.junit.CreateTppCallback
import com.forgerock.sapi.gateway.ob.uk.support.account.AccountRS
import com.forgerock.sapi.gateway.ob.uk.support.account.v4.AccountFactory
import com.forgerock.sapi.gateway.ob.uk.tests.functional.account.access.BaseAccountApi4_0_0
import com.forgerock.sapi.gateway.uk.common.shared.api.meta.obie.OBVersion
import uk.org.openbanking.datamodel.v4.account.OBInternalPermissions1Code
import uk.org.openbanking.datamodel.v4.account.OBReadStandingOrder6

class GetAccountStandingOrders(version: OBVersion, tppResource: CreateTppCallback.TppResource) :
        BaseAccountApi4_0_0(version, tppResource) {

    fun shouldGetAccountStandingOrdersTest() {
        // Given
        val permissions =
                listOf(OBInternalPermissions1Code.READACCOUNTSDETAIL, OBInternalPermissions1Code.READSTANDINGORDERSDETAIL)
        val (_, accessToken) = accountAccessConsentApi.createConsentAndGetAccessToken(permissions)

        // When
        val result = AccountRS().getAccountsData<OBReadStandingOrder6>(
                AccountFactory.urlWithAccountId(
                        accountsApiLinks.GetAccountStandingOrders,
                        USER_ACCOUNT_ID
                ), accessToken
        )

        // Then
        assertThat(result).isNotNull()
        assertThat(result.data.standingOrder).isNotEmpty()
    }

    fun shouldGetAccountStandingOrdersTest_getV4Fields() {
        // Given
        val permissions =
                listOf(OBInternalPermissions1Code.READACCOUNTSDETAIL, OBInternalPermissions1Code.READSTANDINGORDERSDETAIL)
        val (_, accessToken) = accountAccessConsentApi.createConsentAndGetAccessToken(permissions)

        // When
        val result = AccountRS().getAccountsData<OBReadStandingOrder6>(
                AccountFactory.urlWithAccountId(
                        accountsApiLinks.GetAccountStandingOrders,
                        USER_ACCOUNT_ID
                ), accessToken
        )

        val allHaveMandateRelatedInformation = result.data.standingOrder.all { it.mandateRelatedInformation != null }
        val allHaveRemittanceInformation = result.data.standingOrder.all { it.remittanceInformation != null }

        // Then
        assertThat(result).isNotNull()
        assertThat(allHaveMandateRelatedInformation).isNotNull()
        assertThat(allHaveRemittanceInformation).isNotNull()
        assertThat(result.data.standingOrder).isNotEmpty()
    }
}