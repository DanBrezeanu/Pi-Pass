DB_ERROR recalculate_header_len(struct CredentialHeader *crh) {
    if (crh == NULL)
        return ERR_RECALC_HEADER_INV_PARAMS;

    crh->cred_len = crh->name_len + crh->username_len + crh->passw_len +
        crh->url_len + crh->additional_len;

    return DB_OK;
}