path = r"c:\Users\sgwalls\Documents\AWS_Projects\Scripts\Python\Git_repository\Walls-AWS\docs\AWS_MultiAccount_Strategy_Policy.md"

with open(path, encoding="utf-8") as f:
    content = f.read()

old = "# Globe Life : AWS Multi-Account Strategy\n\n**Version:** 1.0  \n**Status:** Draft  \n**Owner:** I.T. Design & Delivery - Cloud Architecture  \n**Author:** Scott Walls\n\n---"
new_top = "# Globe Life : AWS Multi-Account Strategy\n\n---"
content = content.replace(old, new_top, 1)

version_table = "\n---\n\n| Field | Detail |\n|---|---|\n| **Version** | 1.0 |\n| **Status** | Draft |\n| **Owner** | I.T. Design & Delivery - Cloud Architecture |\n| **Author** | Scott Walls |\n"
content = content.rstrip() + "\n" + version_table

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("Done")
