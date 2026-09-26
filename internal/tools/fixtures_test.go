package tools

// userinfoJSON is a canned GetCurrentUser200Response body. "sub" is the only
// required property (see model_get_current_user_200_response.go); the rest
// are included for realism.
const userinfoJSON = `{"sub":"user-123","email":"user@example.com","name":"Test User","idp":"tmi"}`

// userJSON is a canned User (required: principal_type, provider, provider_id,
// display_name, email; see model_user.go).
const userJSON = `{"principal_type":"user","provider":"tmi","provider_id":"u1","display_name":"Alice","email":"alice@example.com"}`

// threatModelJSON is a canned ThreatModel (required: name, owner,
// threat_model_framework, authorization; see model_threat_model.go).
const threatModelJSON = `{"id":"tm-1","name":"TM1","owner":` + userJSON + `,"threat_model_framework":"STRIDE","authorization":[{"principal_type":"user","provider":"tmi","provider_id":"u1","role":"owner"}]}`

// listThreatModelsJSON is a canned ListThreatModelsResponse (required:
// threat_models, total, limit, offset; see model_list_threat_models_response.go).
// Its items are TMListItem (required: id, name, created_at, modified_at,
// owner, created_by, threat_model_framework, document_count, repo_count,
// diagram_count, threat_count, asset_count, note_count; see model_tm_list_item.go).
const listThreatModelsJSON = `{"threat_models":[{"id":"tm-1","name":"TM1","created_at":"2024-01-01T00:00:00Z","modified_at":"2024-01-01T00:00:00Z","owner":` + userJSON + `,"created_by":` + userJSON + `,"threat_model_framework":"STRIDE","document_count":3,"repo_count":0,"diagram_count":0,"threat_count":0,"asset_count":0,"note_count":0}],"total":1,"limit":5,"offset":0}`
