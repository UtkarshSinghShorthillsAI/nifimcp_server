import sys
import os

# Add the 'src' directory to Python's path
# This allows Python to find 'nifimcp_server' as a package
project_root = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(project_root, "nifimcp_server/src/app.py")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

if __name__ == "__main__":
    # Now import and run the app from within the src structure
    from nifimcp_server.app import mcp_app, register_tools
    
    register_tools()
    print("Starting NiFiMCP Server (stdio transport via run_server.py)...")
    mcp_app.run()