path = r"c:\Users\sgwalls\Documents\AWS_Projects\Scripts\Python\Git_repository\Walls-AWS\docs\AWS_MultiAccount_Strategy_Policy.md"
with open(path, encoding="utf-8") as f:
    content = f.read()
print("TOP 200:", repr(content[:200]))
print("BOTTOM 300:", repr(content[-300:]))
