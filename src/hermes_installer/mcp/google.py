from .adapters import MCPService,ReadOnlyAdapter
READ_TOOLS={"gmail":{"search_emails","get_email","list_labels"},"drive":{"search_files","get_file","list_files"},"docs":{"get_document","export_document"},"sheets":{"get_spreadsheet","get_values","list_sheets"},"calendar":{"list_events","get_event","list_calendars"},"contacts":{"search_contacts","get_contact","list_contacts"}}
def adapter(client,*,service:str,resource_id:str,preview_eligible:bool):
    if service not in READ_TOOLS:raise ValueError("unsupported Google service")
    if not preview_eligible:raise PermissionError("Developer Preview eligibility unverified")
    policy=MCPService("google-"+service,None,frozenset(READ_TOOLS[service]),"Developer Preview OAuth","selected resource")
    return ReadOnlyAdapter(policy,client,resource_id)
