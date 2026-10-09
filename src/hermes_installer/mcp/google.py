from .adapters import MCPService,ReadOnlyAdapter
READ_TOOLS={"gmail":{"search_emails","get_email","list_labels"},"drive":{"search_files","get_file","list_files"},"docs":{"get_document","export_document"},"sheets":{"get_spreadsheet","get_values","list_sheets"},"calendar":{"list_events","get_event","list_calendars"},"contacts":{"search_contacts","get_contact","list_contacts"}}
def adapter(client,*,service:str,resource_id:str):
    """Build a read-only catalog adapter; this does not assert account eligibility.

    Live inspection and reads still require the root-issued MCP authority path.
    Google preview/account eligibility remains unavailable until the host can
    verify the actual selected account and reviewed provider policy.
    """
    if service not in READ_TOOLS:raise ValueError("unsupported Google service")
    policy=MCPService("google-"+service,None,frozenset(READ_TOOLS[service]),"Developer Preview OAuth","selected resource")
    return ReadOnlyAdapter(policy,client,resource_id)
