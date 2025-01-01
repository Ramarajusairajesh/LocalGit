#**LocalGit: A Decentralized Git-Like System for LAN and Peer-to-Peer Collaboration**

LocalGit is a lightweight, barebones implementation of Git, designed to emulate core GitHub functionalities like pull and push while addressing the limitations of internet dependency. Built entirely in C++, it serves as a localized version control solution, ideal for environments with unreliable internet or where local network (LAN) infrastructure is the primary mode of communication.

Key Features:
Local Hosting on LAN
LocalGit allows any machine on the LAN to act as a server for hosting and sharing repositories. This eliminates the need for constant internet connectivity, making it ideal for educational institutions, research labs, or other localized environments.

Peer-to-Peer (P2P) Data Sharing
In cases where the central server becomes unavailable (due to failure, shutdown, etc.), LocalGit seamlessly transitions to a peer-to-peer (P2P) model. This ensures that files can still be shared directly between the author and users.

Redundant Data Access
If neither the server nor the author is available, LocalGit tracks users who have downloaded the latest version of a repository. It pings those users' machines to identify available hosts and establishes a connection between the client and the user with the latest version. This decentralized redundancy minimizes downtime and ensures uninterrupted collaboration.

Simple and Efficient
LocalGit is lightweight and purpose-built for LAN-based workflows. Its minimalistic design makes it easy to set up and use without the complexities of larger distributed systems.

Use Case:
LocalGit is perfect for environments where:

Internet connectivity is unreliable or unavailable.
Local networks need an efficient way to share code and files.
Redundancy is essential to ensure continuous access to the latest files.
With LocalGit, collaboration becomes seamless, even in challenging network conditions. By leveraging LAN and P2P fallback mechanisms, it ensures that critical data is always accessible—no matter the situation.

