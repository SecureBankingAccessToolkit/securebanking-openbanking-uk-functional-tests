package com.forgerock.sapi.gateway.ob.uk.tests.functional.account.balances.api.v3_1_8

import assertk.assertThat
import assertk.assertions.isNotEmpty
import assertk.assertions.isNotNull
import com.forgerock.sapi.gateway.framework.extensions.junit.CreateTppCallback
import com.forgerock.sapi.gateway.ob.uk.support.account.AccountRS
import com.forgerock.sapi.gateway.uk.common.shared.api.meta.obie.OBVersion
import com.forgerock.sapi.gateway.ob.uk.tests.functional.account.access.BaseAccountApi3_1_8
import uk.org.openbanking.datamodel.common.OBExternalPermissions1Code
import uk.org.openbanking.datamodel.account.OBReadBalance1

class GetBalances(version: OBVersion, tppResource: CreateTppCallback.TppResource): BaseAccountApi3_1_8(version, tppResource) {
    fun shouldGetBalancesTest() {
        // Given
        val permissions = listOf(
            OBExternalPermissions1Code.READACCOUNTSDETAIL,
            OBExternalPermissions1Code.READBALANCES
        )
        val (_, accessToken) = accountAccessConsentApi.createConsentAndGetAccessToken(permissions)

        // When
        val result = AccountRS().getAccountsData<OBReadBalance1>(
            accountsApiLinks.GetBalances, accessToken
        )

        // Then
        assertThat(result).isNotNull()
        assertThat(result.data.balance).isNotEmpty()
    }
}
