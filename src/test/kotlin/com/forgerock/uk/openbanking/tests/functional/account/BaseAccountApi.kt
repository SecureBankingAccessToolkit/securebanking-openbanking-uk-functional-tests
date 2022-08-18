package com.forgerock.uk.openbanking.tests.functional.account

import com.forgerock.securebanking.framework.extensions.junit.CreateTppCallback
import com.forgerock.securebanking.openbanking.uk.common.api.meta.obie.OBVersion
import com.forgerock.uk.openbanking.support.discovery.getAccountsApiLinks
import com.forgerock.uk.openbanking.tests.functional.account.access.consents.AccountAccessConsentApi

/**
 * Base class for Accounts Api classes to extend from, provides an AccountAccessConsentApi instance which can be
 * used to obtain the consents required to carry out Api operations.
 */
open class BaseAccountApi(
    val version: OBVersion,
    val accountAccessConsentApi: AccountAccessConsentApi,
    val tppResource: CreateTppCallback.TppResource
) {
    protected val accountsApiLinks = getAccountsApiLinks(version)
}
