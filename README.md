## Patcher with Themida SDK

I no longer engage in software cracking, so I thought I'd post my patcher. This is a simple patcher I built using the Themida SDK and some custom macros.

Key Files
   - patcher/src/patcher.cpp: Main patcher logic.
   - patcher-no-ai.cpp: Legacy version, written without using ai.
   - x64dbg_to_patcher/x64dbg_to_patcher.py: Converts x64dbg patch files to a format compatible with the patcher.

Usage
   - Create a Pastebin with your patch configurationand and update the Pastebin URL in patcher/src/patcher.cpp
   - Open patcher.sln and build It
   - Run the Patcher/ It will fetch the patch configuration from the Pastebin URL and apply the patches to the target processes.
