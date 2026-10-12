import base64,importlib.util,math,unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from hermes_installer.remote.gateway import GatewayDenied,RemotePolicy,validate_access_jwt
HAS_CRYPTO=importlib.util.find_spec("jwt") is not None and importlib.util.find_spec("cryptography") is not None
@unittest.skipUnless(HAS_CRYPTO,"install remote CPython3.14 ARM64 pinned dependency lock")
class SignedAccessJwtTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  import jwt
  from cryptography.hazmat.primitives.asymmetric import rsa
  cls.jwt=jwt;cls.key=rsa.generate_private_key(public_exponent=65537,key_size=2048);pub=cls.key.public_key().public_numbers()
  def b64(n):return base64.urlsafe_b64encode(n.to_bytes((n.bit_length()+7)//8,"big")).rstrip(b"=").decode()
  cls.policy=RemotePolicy("desk.example.net","https://team.cloudflareaccess.com","app-aud",frozenset({"owner@example.net"}),{"fixture-kid":{"kty":"RSA","kid":"fixture-kid","alg":"RS256","use":"sig","n":b64(pub.n),"e":b64(pub.e)}})
 @classmethod
 def token(cls,**overrides):
  claims={"iss":cls.policy.issuer,"aud":[cls.policy.audience],"iat":1700000000,"nbf":1700000000,"exp":1700000060,"sub":"subject-1","email":"owner@example.net"};claims.update(overrides)
  return cls.jwt.encode(claims,cls.key,algorithm="RS256",headers={"kid":"fixture-kid"})
 def test_real_signature_and_fixed_claims(self):
  p=validate_access_jwt(self.token(),policy=self.policy,now=lambda:1700000010);self.assertEqual(p.subject,"subject-1");self.assertEqual(p.email,"owner@example.net")
  p=validate_access_jwt(self.token(aud=["app-aud"]),policy=self.policy,now=lambda:1700000010);self.assertEqual(p.subject,"subject-1")
  with self.assertRaises(GatewayDenied):validate_access_jwt(self.token(),policy=self.policy,now=lambda:1700000060)
  with self.assertRaises(GatewayDenied):validate_access_jwt(self.token(),policy=self.policy,now=lambda:float("inf"))
  with self.assertRaises(GatewayDenied):validate_access_jwt(self.token(),policy=self.policy,now=lambda:1700000000-31)
  for token in (self.token(aud=["app-aud","other"]),self.token(aud="wrong-app"),self.token(iss="https://evil.cloudflareaccess.com"),self.token(email="intruder@example.net"),self.token(iat=math.inf),self.token(exp=True),self.token(nbf=1700000100)):
   with self.subTest(token=token[:20]),self.assertRaises(GatewayDenied):validate_access_jwt(token,policy=self.policy,now=lambda:1700000010)
 def test_wrong_signing_algorithm_is_denied(self):
  token=self.jwt.encode({"iss":self.policy.issuer,"aud":self.policy.audience},"unused",algorithm="HS256",headers={"kid":"fixture-kid"})
  with self.assertRaises(GatewayDenied):validate_access_jwt(token,policy=self.policy)
  unsigned=self.jwt.encode({"iss":self.policy.issuer,"aud":self.policy.audience,
   "iat":1700000000,"nbf":1700000000,"exp":1700000060,"sub":"subject-1",
   "email":"owner@example.net"},key="",algorithm="none")
  with self.assertRaises(GatewayDenied):validate_access_jwt(unsigned,policy=self.policy)
 def test_three_allowed_emails_keep_signed_subject_ownership_without_directory(self):
  from hermes_installer.remote.jarvis_chat import JarvisChatDenied,JarvisChatStore
  emails=("owner@example.net","member-one@example.net","member-two@example.net")
  policy=RemotePolicy("desk.example.net",self.policy.issuer,self.policy.audience,
   frozenset(emails),self.policy.jwks)
  principals=[]
  with TemporaryDirectory() as directory:
   # Admission and subject-owned storage must work without optional directory enrollment.
   store=JarvisChatStore(Path(directory)/"chat.sqlite3")
   for index,email in enumerate(emails,1):
    token=self.jwt.encode({"iss":policy.issuer,"aud":[policy.audience],"iat":1700000000,
     "nbf":1700000000,"exp":1700000060,"sub":f"subject-{index}","email":email},
     self.key,algorithm="RS256",headers={"kid":"fixture-kid"})
    identity=validate_access_jwt(token,policy=policy,now=lambda:1700000010)
    principals.append(identity)
    created=store.create_conversation(identity.subject,f"runtime-{index}",f"stored-{index}","core-a")
    self.assertEqual([row["id"] for row in store.list_conversations(identity.subject)],
     [created["id"]])
   first=store.list_conversations(principals[0].subject)[0]
   for identity in principals[1:]:
    with self.assertRaises(JarvisChatDenied):
     store.get_conversation(identity.subject,first["id"])
   same_email_other_subject=self.jwt.encode({"iss":policy.issuer,"aud":[policy.audience],
    "iat":1700000000,"nbf":1700000000,"exp":1700000060,"sub":"new-subject",
    "email":emails[0]},self.key,algorithm="RS256",headers={"kid":"fixture-kid"})
   other=validate_access_jwt(same_email_other_subject,policy=policy,now=lambda:1700000010)
   self.assertEqual(store.list_conversations(other.subject),[])
   with self.assertRaises(JarvisChatDenied):
    store.get_conversation(other.subject,first["id"])
  outsider=self.jwt.encode({"iss":policy.issuer,"aud":[policy.audience],"iat":1700000000,
   "nbf":1700000000,"exp":1700000060,"sub":"outsider-subject",
   "email":"outsider@example.net"},self.key,algorithm="RS256",headers={"kid":"fixture-kid"})
  with self.assertRaises(GatewayDenied):
   validate_access_jwt(outsider,policy=policy,now=lambda:1700000010)
