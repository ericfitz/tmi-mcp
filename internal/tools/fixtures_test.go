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

// diagramNodeJSON and diagramEdgeJSON are a canned Node and Edge cell
// (model_node.go, model_edge.go, model_cell.go, model_edge_terminal.go): a
// realistic pair exercising DfdDiagram's oneOf Node/Edge cell decode, not an
// empty cells array.
const diagramNodeJSON = `{"id":"11111111-1111-1111-1111-111111111111","shape":"actor","position":{"x":10,"y":20},"size":{"width":40,"height":40}}`
const diagramEdgeJSON = `{"id":"22222222-2222-2222-2222-222222222222","shape":"flow","source":{"cell":"11111111-1111-1111-1111-111111111111"},"target":{"cell":"11111111-1111-1111-1111-111111111111"}}`

// diagramJSON is a canned DfdDiagram (required: cells, id, name, created_at,
// modified_at, plus type from the embedded BaseDiagram; see
// model_dfd_diagram.go, model_base_diagram.go). cells holds one real node
// and one real edge so decoding it exercises DfdDiagram's typed decode path,
// not just an empty array.
const diagramJSON = `{"id":"dg-1","name":"Diagram1","type":"DFD","cells":[` + diagramNodeJSON + `,` + diagramEdgeJSON + `],"created_at":"2024-01-01T00:00:00Z","modified_at":"2024-01-01T00:00:00Z"}`

// diagramWithUnknownFieldJSON is diagramJSON plus a field absent from the
// vendored client's spec. Every generated model decodes with
// DisallowUnknownFields, so this is a genuine decode error from a
// successful (2xx) response — the case rawOnDecodeErr guards against.
const diagramWithUnknownFieldJSON = `{"id":"dg-1","name":"Diagram1","type":"DFD","cells":[],"created_at":"2024-01-01T00:00:00Z","modified_at":"2024-01-01T00:00:00Z","future_field":"x"}`

// diagramListItemJSON is a canned DiagramListItem (required: id, name, type,
// created_at, modified_at; see model_diagram_list_item.go).
const diagramListItemJSON = `{"id":"dg-1","name":"Diagram1","type":"DFD","created_at":"2024-01-01T00:00:00Z","modified_at":"2024-01-01T00:00:00Z"}`

// listDiagramsJSON is a canned ListDiagramsResponse (required: diagrams,
// total, limit, offset; see model_list_diagrams_response.go).
const listDiagramsJSON = `{"diagrams":[` + diagramListItemJSON + `],"total":1,"limit":20,"offset":0}`

// minimalDiagramModelJSON is a canned MinimalDiagramModel (required: id,
// name, description, metadata, cells, assets; see model_minimal_diagram_model.go).
const minimalDiagramModelJSON = `{"id":"dg-1","name":"Diagram1","description":"desc","metadata":{},"cells":[],"assets":[]}`

// assetJSON is a canned Asset (required: name, type, id; see model_asset.go).
const assetJSON = `{"id":"a-1","name":"Asset1","type":"software"}`

// listAssetsJSON is a canned ListAssetsResponse (required: assets, total,
// limit, offset; see model_list_assets_response.go).
const listAssetsJSON = `{"assets":[` + assetJSON + `],"total":1,"limit":20,"offset":0}`

// documentJSON is a canned Document (required: name, uri, id; see model_document.go).
const documentJSON = `{"id":"doc-1","name":"Document1","uri":"https://example.com/doc"}`

// listDocumentsJSON is a canned ListDocumentsResponse (required: documents,
// total, limit, offset; see model_list_documents_response.go).
const listDocumentsJSON = `{"documents":[` + documentJSON + `],"total":1,"limit":20,"offset":0}`

// noteJSON is a canned Note (required: name, content, id; see model_note.go).
const noteJSON = `{"id":"note-1","name":"Note1","content":"note text"}`

// noteListItemJSON is a canned NoteListItem (required: name, id; the decoder
// rejects unknown fields, so it cannot reuse noteJSON's "content"; see
// model_note_list_item.go).
const noteListItemJSON = `{"id":"note-1","name":"Note1"}`

// listNotesJSON is a canned ListNotesResponse (required: notes, total,
// limit, offset; items are NoteListItem; see
// model_list_notes_response.go, model_note_list_item.go).
const listNotesJSON = `{"notes":[` + noteListItemJSON + `],"total":1,"limit":20,"offset":0}`

// repositoryJSON is a canned Repository (required: uri, id; see model_repository.go).
const repositoryJSON = `{"id":"repo-1","uri":"https://github.com/example/repo"}`

// listRepositoriesJSON is a canned ListRepositoriesResponse (required:
// repositories, total, limit, offset; see model_list_repositories_response.go).
const listRepositoriesJSON = `{"repositories":[` + repositoryJSON + `],"total":1,"limit":20,"offset":0}`
