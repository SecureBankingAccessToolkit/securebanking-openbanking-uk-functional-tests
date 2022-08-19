package com.forgerock.uk.openbanking.tests.functional.account.transactions.api.v3_1_8

import assertk.assertThat
import assertk.assertions.isNotEmpty
import assertk.assertions.isNotNull
import com.forgerock.securebanking.framework.extensions.junit.CreateTppCallback
import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion
import com.forgerock.uk.openbanking.support.account.AccountFactory
import com.forgerock.uk.openbanking.support.account.AccountRS
import com.forgerock.uk.openbanking.tests.functional.account.access.BaseAccountApi3_1_8
import uk.org.openbanking.datamodel.account.OBExternalPermissions1Code
import uk.org.openbanking.datamodel.account.OBReadTransaction6

class GetAccountTransactions(version: OBVersion, tppResource: CreateTppCallback.TppResource) :
    BaseAccountApi3_1_8(version, tppResource) {

    fun shouldGetAccountTransactionsTest() {
        // Given
        val permissions = listOf(
            OBExternalPermissions1Code.READACCOUNTSDETAIL,
            OBExternalPermissions1Code.READTRANSACTIONSCREDITS,
            OBExternalPermissions1Code.READTRANSACTIONSDEBITS,
            OBExternalPermissions1Code.READTRANSACTIONSDETAIL
        )
        val (_, accessToken) = accountAccessConsentApi.createConsentAndGetAccessToken(permissions)
        val accountId = AccountRS().getFirstAccountId(accountsApiLinks.GetAccounts, accessToken)

        // When
        val result = AccountRS().getAccountsData<OBReadTransaction6>(
            AccountFactory.urlWithAccountId(
                accountsApiLinks.GetAccountTransactions,
                accountId
            ), accessToken
        )

        // Then
        assertThat(result).isNotNull()
        assertThat(result.data.transaction).isNotEmpty()
    }
}