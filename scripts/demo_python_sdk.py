from tesht import TeshtClient

c = TeshtClient("http://localhost:8000")

agent = c.create_agent("issuer-1")
print("AGENT", agent)

issued = c.issue_credential(
    issuer_agent_id=agent["id"],
    subject_did="did:web:example.com:subject:123",
    credential_type="AgentCredential",
)
print("ISSUED", issued["credential_id"]) 

verified = c.verify_credential(issued["jwt"])
print("VERIFIED", verified["verified"], verified.get("reason"))

revoked = c.revoke_credential(issued["credential_id"])
print("REVOKED", revoked)

verified2 = c.verify_credential(issued["jwt"])
print("VERIFIED_AFTER_REVOKE", verified2["verified"], verified2.get("reason"))
