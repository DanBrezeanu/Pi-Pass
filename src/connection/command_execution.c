#include <commands.h>
#include <connection.h>
#include <command_execution.h>
#include <commands_utils.h>
#include <crypto.h>
#include <flags.h>
#include <aes256.h>
#include <authentication.h>
#include <actions.h>

static uint8_t *auth_token = NULL;

static PIPASS_ERR _execute_app_hello(Cmd *cmd);
static PIPASS_ERR _execute_ask_for_pin(Cmd *cmd);
static PIPASS_ERR _execute_ask_for_password(Cmd *cmd);
static PIPASS_ERR _execute_list_credentials(Cmd *cmd);
static PIPASS_ERR _execute_credential_details(Cmd *cmd);
static PIPASS_ERR _execute_encrypted_field_value(Cmd *cmd);
static PIPASS_ERR _execute_add_credential(Cmd *cmd);


PIPASS_ERR _execute_command(Cmd *cmd) {
    if (cmd == NULL)
        return ERR_SEND_CMD_INV_PARAMS;

    PIPASS_ERR err = PIPASS_OK;
    json_object *type = NULL;

    if (!json_object_object_get_ex(cmd->body, "type", &type) 
        || json_object_get_type(type) != json_type_int)
        return ERR_JSON_INVALID_KEY;

    switch (json_object_get_int(type)) {
    case APP_HELLO:
        return _execute_app_hello(cmd);
        break;
    case ASK_FOR_PIN:
        return _execute_ask_for_pin(cmd);
        break;
    case ASK_FOR_PASSWORD:
        return _execute_ask_for_password(cmd);
        break;
    case LIST_CREDENTIALS:
        return _execute_list_credentials(cmd);
    case CREDENTIAL_DETAILS:
        return _execute_credential_details(cmd);
    case ENCRYPTED_FIELD_VALUE:
        return _execute_encrypted_field_value(cmd);
    case ADD_CREDENTIAL:
        return _execute_add_credential(cmd);
    default:
        err = ERR_UNKNOWN_COMMAND;
        break;
    }

    return err;
}


static PIPASS_ERR _execute_app_hello(Cmd *cmd) {
    PIPASS_ERR err;
    Cmd *cmd_hello = NULL;

    json_object *sender = NULL;
    json_object *is_reply = NULL;

    printf("Sending HELLO reply\n");

    if (!json_object_object_get_ex(cmd->body, "sender", &sender) 
        || json_object_get_type(sender) != json_type_int)
        return ERR_JSON_INVALID_KEY;

    if (!json_object_object_get_ex(cmd->body, "is_reply", &is_reply) 
        || json_object_get_type(is_reply) != json_type_boolean)
        return ERR_JSON_INVALID_KEY;

    if (json_object_get_int(sender) == SENDER_APP && !json_object_get_boolean(is_reply)) {
        
        /* Create reply */
        err = create_command(APP_HELLO, &cmd_hello);
        if (err != PIPASS_OK)
            goto error;

        /* Set options to either 0 or 1 depending if the device was unlocked */
        err = json_object_object_add(cmd_hello->body, "options", json_object_new_string(((FL_DB_INITIALIZED && FL_LOGGED_IN) ? "1" : "0")));
        if (err != PIPASS_OK)
            return ERR_CMD_JSON_ADD;

        printf("Before send_command\n");

        err = send_command(cmd_hello);
        if (err != PIPASS_OK)
            goto error;

        return PIPASS_OK;
    } else {
        err = ERR_CONN_INVALID_COMM;
        goto error;
    }

    err = PIPASS_OK;

error:
    free_command(&cmd_hello);
    return err;
}

static PIPASS_ERR _execute_ask_for_pin(Cmd *cmd) {
    PIPASS_ERR err;
    Cmd *cmd_send_pin = NULL;

    uint8_t *recvd_pin = NULL;

    json_object *sender   = NULL;
    json_object *is_reply = NULL;
    json_object *json_pin      = NULL;

    if (!json_object_object_get_ex(cmd->body, "sender", &sender) 
        || json_object_get_type(sender) != json_type_int)
        return ERR_JSON_INVALID_KEY;

    if (!json_object_object_get_ex(cmd->body, "is_reply", &is_reply) 
        || json_object_get_type(is_reply) != json_type_boolean)
        return ERR_JSON_INVALID_KEY;

    if (json_object_get_int(sender) == SENDER_APP && !json_object_get_boolean(is_reply)) {

        /* Create reply */
        err = create_command(ASK_FOR_PIN, &cmd_send_pin);
        if (err != PIPASS_OK)
            goto error;
        
        if (!FL_DB_INITIALIZED || !FL_LOGGED_IN) {
            goto reply_with_error;
        }
        
        /* Check pin was received */
        if (!json_object_object_get_ex(cmd->body, "options", &json_pin) ||
            json_object_get_type(json_pin) != json_type_string) {

           goto reply_with_error;
        } 

        /* Check pin size */
        if (json_object_get_string_len(json_pin) != MASTER_PIN_SIZE) {
            goto reply_with_error;
        }

        /* Check pin is correct */
        err = verify_master_pin_with_db(json_object_get_string(json_pin));
        if (err != PIPASS_OK) {
            goto reply_with_error;
        }
        printf("err verify_with_db: %.4X\n", err);

        /* Set new auth_token */
        if (auth_token != NULL) {
            erase_buffer(&auth_token, AUTH_TOKEN_SIZE);
        }
        
        err = get_rand_auth_token(&auth_token);
        if (err != PIPASS_OK)
            goto error;

        err = json_object_object_add(cmd_send_pin->body, "auth_token", json_object_new_string(auth_token));
        if (err != PIPASS_OK)
            return ERR_CMD_JSON_ADD;

        goto send;

    } else {
        err = ERR_PIN_NOT_ENTERED;
        goto error;
    }

reply_with_error:
    err = json_object_object_add(cmd_send_pin->body, "reply_code", json_object_new_int(1));
    if (err != PIPASS_OK) {
        err = ERR_CMD_JSON_ADD;
        goto error;
    }

send:
    err = send_command(cmd_send_pin);
    if (err != PIPASS_OK)
        goto error;

error:
    free_command(&cmd_send_pin);

    return err;
}

static PIPASS_ERR _execute_ask_for_password(Cmd *cmd) {
    PIPASS_ERR err;
    Cmd *cmd_ask_passw = NULL;

    json_object *sender = NULL;
    json_object *is_reply = NULL;
    json_object *options = NULL;

    printf("Sending ASK FOR PASSW reply\n");

    if (!json_object_object_get_ex(cmd->body, "sender", &sender) 
        || json_object_get_type(sender) != json_type_int)
        return ERR_JSON_INVALID_KEY;

    if (!json_object_object_get_ex(cmd->body, "is_reply", &is_reply) 
        || json_object_get_type(is_reply) != json_type_boolean)
        return ERR_JSON_INVALID_KEY;

    if (json_object_get_int(sender) == SENDER_APP && json_object_get_boolean(is_reply)) {
        FL_RECEIVED_PASSWORD = 1;
        
        json_object_object_get_ex(cmd->body, "options", &options);
        printf("Password received: %s\n", json_object_get_string(options));

        uint8_t *user = NULL;
        err = get_user(&user);
        err = authenticate(user, strlen(user), entered_pin, NULL, json_object_get_string(options), json_object_get_string_len(options));
        printf("user: %s   pin: %s passw: %s err: %X", user, entered_pin, json_object_get_string(options), err);
        
        /* Create reply */
        err = create_command(ASK_FOR_PASSWORD, &cmd_ask_passw);
        if (err != PIPASS_OK)
            goto error;

        /* Set options to either 0 or 1 depending if the device was unlocked */
        err = json_object_object_add(cmd_ask_passw->body, "options", json_object_new_string(((FL_DB_INITIALIZED && FL_LOGGED_IN) ? "1" : "0")));
        if (err != PIPASS_OK)
            return ERR_CMD_JSON_ADD;

        printf("Before send_command\n");

        err = send_command(cmd_ask_passw);
        if (err != PIPASS_OK)
            goto error;

        return PIPASS_OK;
    } else {
        err = ERR_CONN_INVALID_COMM;
        goto error;
    }

    err = PIPASS_OK;

error:
    free_command(&cmd_ask_passw);
    return err;
}

static PIPASS_ERR _execute_list_credentials(Cmd *cmd) {
    PIPASS_ERR err;
    Cmd *cmd_list_cred = NULL;

    json_object *sender = NULL;
    json_object *is_reply = NULL;
    json_object *options = NULL;

    printf("Sending LIST_CRED reply\n");

    if (!json_object_object_get_ex(cmd->body, "sender", &sender) 
        || json_object_get_type(sender) != json_type_int)
        return ERR_JSON_INVALID_KEY;

    if (!json_object_object_get_ex(cmd->body, "is_reply", &is_reply) 
        || json_object_get_type(is_reply) != json_type_boolean)
        return ERR_JSON_INVALID_KEY;

    if (json_object_get_int(sender) == SENDER_APP && !json_object_get_boolean(is_reply)) {
        
        /* Create reply */
        err = create_command(LIST_CREDENTIALS, &cmd_list_cred);
        if (err != PIPASS_OK)
            goto error;

        uint8_t **credential_names = NULL;
        uint8_t **credential_urls = NULL;
        json_object *cred_details = NULL;
        uint16_t credential_count = 0;

        err = get_credential_names(&credential_names, &credential_urls, &credential_count);
        if (err != PIPASS_OK)
            goto error;

        options = json_object_new_array();
        for (uint16_t i = 0; i < credential_count; ++i) {
            cred_details = json_object_new_object();
            json_object_object_add(cred_details, "name",  json_object_new_string(credential_names[i]));
            json_object_object_add(cred_details, "url", json_object_new_string(credential_urls[i]));

            err = json_object_array_add(options, cred_details);
            if (err != PIPASS_OK)
                return ERR_CMD_JSON_ADD;
        }
        

        err = json_object_object_add(cmd_list_cred->body, "options", options);
        if (err != PIPASS_OK)
            return ERR_CMD_JSON_ADD;

        printf("Before send_command\n");

        err = send_command(cmd_list_cred);
        if (err != PIPASS_OK)
            goto error;

        return PIPASS_OK;
    } else {
        err = ERR_CONN_INVALID_COMM;
        goto error;
    }

    err = PIPASS_OK;

error:
    free_command(&cmd_list_cred);
    return err;
}

static PIPASS_ERR _execute_credential_details(Cmd *cmd) {
    PIPASS_ERR err;
    Cmd *cmd_cred_details = NULL;

    json_object *sender = NULL;
    json_object *is_reply = NULL;
    json_object *options = NULL;
    json_object *reply_options = NULL;

    printf("Sending CRED_DETAILS reply\n");

    if (!json_object_object_get_ex(cmd->body, "sender", &sender) 
        || json_object_get_type(sender) != json_type_int)
        return ERR_JSON_INVALID_KEY;

    if (!json_object_object_get_ex(cmd->body, "is_reply", &is_reply) 
        || json_object_get_type(is_reply) != json_type_boolean)
        return ERR_JSON_INVALID_KEY;

    if (!json_object_object_get_ex(cmd->body, "options", &options) 
        || json_object_get_type(options) != json_type_string)
        return ERR_JSON_INVALID_KEY;

    if (json_object_get_int(sender) == SENDER_APP && !json_object_get_boolean(is_reply)) {
        
        /* Create reply */
        err = create_command(CREDENTIAL_DETAILS, &cmd_cred_details);
        if (err != PIPASS_OK)
            goto error;

        struct Credential *cred = NULL;
        err = get_credential_details(json_object_get_string(options), &cred);
        if (err != PIPASS_OK)
            goto error;


        reply_options = json_object_new_object();
        for (uint16_t i = 0; i < cred->fields_count; ++i) {
            err = json_object_object_add(
                reply_options,
                cred->fields_names[i],
                (!cred->fields_encrypted[i]) ? (json_object_new_string(cred->fields_data[i].data_plain)) : (NULL)
            );
            if (err != PIPASS_OK)
                return ERR_CMD_JSON_ADD;
        }
        

        err = json_object_object_add(cmd_cred_details->body, "options", reply_options);
        if (err != PIPASS_OK)
            return ERR_CMD_JSON_ADD;

        printf("Before send_command\n");

        err = send_command(cmd_cred_details);
        if (err != PIPASS_OK)
            goto error;

        return PIPASS_OK;
    } else {
        err = ERR_CONN_INVALID_COMM;
        goto error;
    }

    err = PIPASS_OK;

error:
    free_command(&cmd_cred_details);
    return err;
}


static PIPASS_ERR _execute_encrypted_field_value(Cmd *cmd) {
    PIPASS_ERR err;
    Cmd *cmd_enc_field = NULL;

    json_object *sender = NULL;
    json_object *is_reply = NULL;
    json_object *options = NULL;
    json_object *credential_name = NULL;
    json_object *field_name = NULL;
    json_object *reply_options = NULL;

    printf("Sending CRED_DETAILS reply\n");

    if (!json_object_object_get_ex(cmd->body, "sender", &sender) 
        || json_object_get_type(sender) != json_type_int)
        return ERR_JSON_INVALID_KEY;

    if (!json_object_object_get_ex(cmd->body, "is_reply", &is_reply) 
        || json_object_get_type(is_reply) != json_type_boolean)
        return ERR_JSON_INVALID_KEY;

    if (!json_object_object_get_ex(cmd->body, "options", &options) 
        || json_object_get_type(options) != json_type_object)
        return ERR_JSON_INVALID_KEY;

    if (!json_object_object_get_ex(options, "credential_name", &credential_name) 
        || json_object_get_type(credential_name) != json_type_string)
        return ERR_JSON_INVALID_KEY;

    if (!json_object_object_get_ex(options, "field_name", &field_name) 
        || json_object_get_type(field_name) != json_type_string)
        return ERR_JSON_INVALID_KEY;

    if (json_object_get_int(sender) == SENDER_APP && !json_object_get_boolean(is_reply)) {
        
        /* Create reply */
        err = create_command(ENCRYPTED_FIELD_VALUE, &cmd_enc_field);
        if (err != PIPASS_OK)
            goto error;

        struct Credential *field_value = NULL;
        err = get_encrypted_field_value(
            json_object_get_string(credential_name),
            json_object_get_string(field_name),
            &field_value
        );

        if (err != PIPASS_OK)
            goto error;

        reply_options = json_object_new_string(field_value);
        err = json_object_object_add(cmd_enc_field->body, "options", reply_options);
        if (err != PIPASS_OK)
            return ERR_CMD_JSON_ADD;

        printf("Before send_command\n");

        err = send_command(cmd_enc_field);
        if (err != PIPASS_OK)
            goto error;

        return PIPASS_OK;
    } else {
        err = ERR_CONN_INVALID_COMM;
        goto error;
    }

    err = PIPASS_OK;

error:
    free_command(&cmd_enc_field);
    return err;
}

static PIPASS_ERR _execute_add_credential(Cmd *cmd) {
    PIPASS_ERR err;
    Cmd *cmd_enc_field = NULL;

    json_object *sender = NULL;
    json_object *is_reply = NULL;
    json_object *options = NULL;
    json_object *credential_type = NULL;
    json_object *credential_fields = NULL;
    json_object *field = NULL;
    json_object *reply_options = NULL;

    uint8_t **fields_names = NULL;
    uint16_t *fields_names_len = NULL;
    uint8_t **fields_data = NULL;
    uint16_t *fields_data_len = NULL;
    uint8_t *fields_encrypted = NULL;

    uint8_t *user = NULL;
    uint8_t *user_hash = NULL;

    printf("Sending ADD_CREDENTIAl reply\n");

    if (!json_object_object_get_ex(cmd->body, "sender", &sender) 
        || json_object_get_type(sender) != json_type_int)
        return ERR_JSON_INVALID_KEY;

    if (!json_object_object_get_ex(cmd->body, "is_reply", &is_reply) 
        || json_object_get_type(is_reply) != json_type_boolean)
        return ERR_JSON_INVALID_KEY;

    if (!json_object_object_get_ex(cmd->body, "options", &options) 
        || json_object_get_type(options) != json_type_object)
        return ERR_JSON_INVALID_KEY;

    if (!json_object_object_get_ex(options, "type", &credential_type) 
        || json_object_get_type(credential_type) != json_type_int ||
        json_object_get_int(credential_type) < 0 || json_object_get_int(credential_type) >= CREDENTIAL_TYPES_COUNT)
        return ERR_JSON_INVALID_KEY;

    if (!json_object_object_get_ex(options, "fields", &credential_fields) 
        || json_object_get_type(credential_fields) != json_type_array)
        return ERR_JSON_INVALID_KEY;

    uint32_t fields_len = json_object_array_length(credential_fields);

    fields_names = calloc(fields_len, sizeof(uint8_t *));
    fields_names_len = calloc(fields_len, sizeof(uint16_t));
    fields_data = calloc(fields_len, sizeof(uint8_t *));
    fields_data_len = calloc(fields_len, sizeof(uint16_t));
    fields_encrypted = calloc(fields_len, sizeof(uint8_t));

    if (json_object_get_int(sender) == SENDER_APP && !json_object_get_boolean(is_reply)) {
        
        /* Create reply */
        err = create_command(ADD_CREDENTIAL, &cmd_enc_field);
        if (err != PIPASS_OK)
            goto error;

        for (uint32_t i = 0; i < fields_len; ++i) {
            json_object *field_name;
            json_object *field_data;
            json_object *field_encrypted;

            field = json_object_array_get_idx(credential_fields, i);
            if (json_object_get_type(field) != json_type_object)
                return ERR_JSON_INVALID_KEY;

            if (!json_object_object_get_ex(field, "name", &field_name) 
                || json_object_get_type(field_name) != json_type_string)
                return ERR_JSON_INVALID_KEY;

            if (!json_object_object_get_ex(field, "data", &field_data) 
                || json_object_get_type(field_data) != json_type_string)
                return ERR_JSON_INVALID_KEY;

            if (!json_object_object_get_ex(field, "encrypted", &field_encrypted) 
                || json_object_get_type(field_encrypted) != json_type_boolean)
                return ERR_JSON_INVALID_KEY;

            fields_names[i] = calloc(json_object_get_string_len(field_name) + 1, sizeof(uint8_t));
            fields_data[i] = calloc(json_object_get_string_len(field_data) + 1, sizeof(uint8_t));

            memcpy(fields_names[i], json_object_get_string(field_name), json_object_get_string_len(field_name));
            memcpy(fields_data[i], json_object_get_string(field_data), json_object_get_string_len(field_data));
            fields_encrypted[i] = json_object_get_boolean(field_encrypted);
            fields_names_len[i] = json_object_get_string_len(field_name);
            fields_data_len[i] = json_object_get_string_len(field_data);
        }


        err = get_user(&user);
        err = generate_user_hash(user, strlen(user), &user_hash);
        err = register_new_credential(
            user_hash,
            (enum CredentialType) json_object_get_int(credential_type),
            fields_len,
            fields_names_len,
            fields_names,
            fields_data_len,
            fields_encrypted,
            fields_data
        );

        if (err != PIPASS_OK)
            goto error;

        reply_options = json_object_new_string("1");
        err = json_object_object_add(cmd_enc_field->body, "options", reply_options);
        if (err != PIPASS_OK)
            return ERR_CMD_JSON_ADD;

        printf("Before send_command\n");

        err = send_command(cmd_enc_field);
        if (err != PIPASS_OK)
            goto error;

        return PIPASS_OK;
    } else {
        err = ERR_CONN_INVALID_COMM;
        goto error;
    }

    err = PIPASS_OK;

error:
    free_command(&cmd_enc_field);
    return err;
}


