Overview

"Fools Mate, Revenge" presents a polished chess web application — an Endgame Trainer — that challenges the player to deliver checkmate in one move. The puzzle itself is trivial (Rook to a8 is an obvious back-rank mate), but the application refuses to give you the flag when you solve it legitimately: a server-side "reward gate" checks a session property that is never set through normal gameplay.

The intended attack vector is Server-Side Prototype Pollution via an unprotected deepMerge() function in the /api/settings endpoint. By injecting properties through JavaScript's prototype chain, we can make the reward gate's authorization check resolve to true without ever directly setting the guarded property.
