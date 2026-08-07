# comment.py
# This module defines the `Commentaireia` class, which provides context-based random comments.
# The comments are based on various themes such as "IDLE", "SCANNER", and others, to simulate
# different states or actions within a network scanning and security context. The class uses a 
# shared data object to determine delays between comments and switches themes based on the current 
# state. The `get_commentaire` method returns a random comment from the specified theme, ensuring 
# comments are not repeated too frequently.

import random
import time
import logging
import json
from init_shared import shared_data  
from logger import Logger
import os

logger = Logger(name="comment.py", level=logging.DEBUG)

def status_lines(sd):
    """Live one-liners for the comment slot — what Bjorn has actually found, in its own voice.

    Counters that are still zero are left out: "0 creds" every third comment is noise pretending to
    be information, and the panel has room for one line. Everything here is an in-memory counter the
    display threads already maintain (the P5 change-gated read), so this costs no file I/O."""
    lines = [f"{sd.targetnbr} alive / {sd.networkkbnbr} known"]
    if sd.portnbr:
        lines.append(f"{sd.portnbr} open ports mapped")
    if sd.vulnnbr:
        lines.append(f"{sd.vulnnbr} weak spots on the board")
    if sd.crednbr:
        lines.append(f"{sd.crednbr} keys on my belt")
    if sd.datanbr:
        lines.append(f"{sd.datanbr} files in the longship")
    if sd.zombiesnbr:
        lines.append(f"{sd.zombiesnbr} thralls still answering")
    if sd.attacksnbr:
        lines.append(f"{sd.attacksnbr} raids logged")
    lines.append(f"Lvl {sd.levelnbr} - {sd.coinnbr} coins")
    if not getattr(sd, "wifi_connected", True):
        lines.append("No uplink. Reading the air.")
    return lines


class Commentaireia:
    """Provides context-based random comments for bjorn."""
    def __init__(self):
        self.shared_data = shared_data
        self.last_comment_time = 0  # Initialize last_comment_time
        self.comment_delay = random.randint(self.shared_data.comment_delaymin, self.shared_data.comment_delaymax)  # Initialize comment_delay
        self.last_theme = None  # Initialize last_theme
        self.comment_count = 0  # drives the joke/status rotation (comment_info_ratio)
        self.themes = self.load_comments(self.shared_data.commentsfile)  # Load themes from JSON file

    def load_comments(self, commentsfile):
        """Load comments from a JSON file."""
        cache_file = commentsfile + '.cache'

        # Check if a cached version exists and is newer than the original file
        if os.path.exists(cache_file) and os.path.getmtime(cache_file) >= os.path.getmtime(commentsfile):
            try:
                with open(cache_file, 'r') as file:
                    comments_data = json.load(file)
                    logger.info("Comments loaded successfully from cache.")
                    return comments_data
            except (FileNotFoundError, json.JSONDecodeError):
                logger.warning("Cache file is corrupted or not found. Loading from the original file.")

        # Load from the original file if cache is not used or corrupted
        try:
            with open(commentsfile, 'r') as file:
                comments_data = json.load(file)
                logger.info("Comments loaded successfully from JSON file.")
                # Save to cache
                with open(cache_file, 'w') as cache:
                    json.dump(comments_data, cache)
                return comments_data
        except FileNotFoundError:
            logger.error(f"The file '{commentsfile}' was not found.")
            return {"IDLE": ["Default comment, no comments file found."]}  # Fallback to a default theme
        except json.JSONDecodeError:
            logger.error(f"The file '{commentsfile}' is not a valid JSON file.")
            return {"IDLE": ["Default comment, invalid JSON format."]}  # Fallback to a default theme

    def get_commentaire(self, theme):
        """ This method returns a random comment based on the specified theme."""
        current_time = time.time()  # Get the current time in seconds
        if theme != self.last_theme or current_time - self.last_comment_time >= self.comment_delay:  # Check if the theme has changed or if the delay has expired
            self.last_comment_time = current_time   # Update the last comment time
            self.last_theme = theme   # Update the last theme

            self.comment_count += 1

            # Every Nth slot reports instead of joking. Same slot, same delay — the panel gains
            # information without losing the character, and one ratio knob tunes the whole balance
            # (0 = jokes only, as before).
            ratio = getattr(self.shared_data, "comment_info_ratio", 3)
            if ratio and self.comment_count % ratio == 0:
                try:
                    return random.choice(status_lines(self.shared_data))
                except Exception as e:  # a missing counter must never cost us the comment
                    logger.debug(f"Status line unavailable, falling back to a comment: {e}")

            if theme not in self.themes:
                logger.warning(f"The theme '{theme}' is not defined, using the default theme IDLE.")
                theme = "IDLE"

            return random.choice(self.themes[theme])  # Return a random comment based on the specified theme
        else:
            return None
