try:
    client_id = '674866541346684938'
    rpc_obj = rpc.DiscordIpcClient.for_platform(client_id)
    print("RPC connection successful.")
    activity = {
        "details": "[ SONG ]",
        "state": "[ AUTHOR ]",
        "assets": {
            "large_image": 'tune',
            "large_text": 'Tune Music',
            "small_image": 'network',
            "small_text": 'Playing'
        },
        "buttons": [
            {"label": "Invite Tune", "url": "https://canary.discord.com/api/oauth2/authorize?client_id=674866541346684938&permissions=412370652481&scope=bot%20applications.commands"}
        ],
    }
    rpc_obj.set_activity(activity)
except:
    pass

while True:
    time.sleep(1)
