#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Spunky Bot - An automated game server bot
http://www.spunkybot.de
Author: Alexander Kress

This program is released under the MIT License. See LICENSE for more details.

## About ##
Spunky Bot is a lightweight game server administration bot and RCON tool,
inspired by the eb2k9 bot by Shawn Haggard.
The purpose of Spunky Bot is to administrate an Urban Terror 4.1 / 4.2 / 4.3
server and provide statistical data for players.

## Configuration ##
Modify the UrT server config as follows:
 * seta g_logsync "1"
 * seta g_loghits "1"
Modify the files '/conf/settings.conf' and '/conf/rules.conf'
Run the bot: python spunky.py
"""

__version__ = '1.8.1024'


### IMPORTS
import os
import time
import sqlite3
import math
import textwrap
import urllib
import urllib2
import platform
import random
import ConfigParser
import logging.handlers
import lib.pygeoip as pygeoip
import lib.schedule as schedule

from lib.pyquake3 import PyQuake3
from Queue import Queue
from threading import Thread
from threading import RLock


# Get an instance of a logger
logger = logging.getLogger('spunkybot')
logger.setLevel(logging.DEBUG)
logger.propagate = False

# Bot player number
BOT_PLAYER_NUM = 1022


### CLASS Log Parser ###
class LogParser(object):
    """
    log file parser
    """
    def __init__(self, config_file):
        """
        create a new instance of LogParser

        @param config_file: The full path of the bot configuration file
        @type  config_file: String
        """
        # hit zone support for UrT > 4.2.013
        self.hit_points = {0: "HEAD", 1: "HEAD", 2: "HELMET", 3: "TORSO", 4: "VEST", 5: "LEFT_ARM", 6: "RIGHT_ARM",
                           7: "GROIN", 8: "BUTT", 9: "LEFT_UPPER_LEG", 10: "RIGHT_UPPER_LEG", 11: "LEFT_LOWER_LEG",
                           12: "RIGHT_LOWER_LEG", 13: "LEFT_FOOT", 14: "RIGHT_FOOT"}
        self.hit_item = {1: "UT_MOD_KNIFE", 2: "UT_MOD_BERETTA", 3: "UT_MOD_DEAGLE", 4: "UT_MOD_SPAS", 5: "UT_MOD_MP5K",
                         6: "UT_MOD_UMP45", 8: "UT_MOD_LR300", 9: "UT_MOD_G36", 10: "UT_MOD_PSG1", 14: "UT_MOD_SR8",
                         15: "UT_MOD_AK103", 17: "UT_MOD_NEGEV", 19: "UT_MOD_M4", 20: "UT_MOD_GLOCK", 21: "UT_MOD_COLT1911",
                         22: "UT_MOD_MAC11", 23: "UT_MOD_BLED"}
        self.death_cause = {1: "MOD_WATER", 3: "MOD_LAVA", 5: "UT_MOD_TELEFRAG", 6: "MOD_FALLING", 7: "UT_MOD_SUICIDE",
                            9: "MOD_TRIGGER_HURT", 10: "MOD_CHANGE_TEAM", 12: "UT_MOD_KNIFE", 13: "UT_MOD_KNIFE_THROWN",
                            14: "UT_MOD_BERETTA", 15: "UT_MOD_DEAGLE", 16: "UT_MOD_SPAS", 17: "UT_MOD_UMP45", 18: "UT_MOD_MP5K",
                            19: "UT_MOD_LR300", 20: "UT_MOD_G36", 21: "UT_MOD_PSG1", 22: "UT_MOD_HK69", 23: "UT_MOD_BLED",
                            24: "UT_MOD_KICKED", 25: "UT_MOD_HEGRENADE", 28: "UT_MOD_SR8", 30: "UT_MOD_AK103",
                            31: "UT_MOD_SPLODED", 32: "UT_MOD_SLAPPED", 33: "UT_MOD_SMITED", 34: "UT_MOD_BOMBED",
                            35: "UT_MOD_NUKED", 36: "UT_MOD_NEGEV", 37: "UT_MOD_HK69_HIT", 38: "UT_MOD_M4",
                            39: "UT_MOD_GLOCK", 40: "UT_MOD_COLT1911", 41: "UT_MOD_MAC11"}

	# RCON commands for the different admin roles
        self.user_cmds = ['bombstats', 'ctfstats', 'freezestats', 'forgiveall, forgiveprev', 'hestats', 'hs',
                          'knife', 'register', 'regtest', 'spree', 'teams', 'time']
        self.mod_cmds = self.user_cmds + ['admintest', 'country', 'leveltest', 'list', 'locate', 'nextmap', 'poke',
                                          'seen', 'warninfo', 'warns', 'warntest']
        self.admin_cmds = self.mod_cmds + ['admins', 'aliases', 'bigtext', 'find', 'lastbans', 'lookup']

        self.fulladmin_cmds = self.admin_cmds + ['baninfo', 'ci', 'rain', 'version', 'say']

	self.senioradmin_cmds = self.fulladmin_cmds + ['banlist', 'cyclemap', 'exec', 'nuke', 'kill', 'warnclear', 'warnremove', 'warn', 'kiss', 'force', 'swap', 'veto', 'scream',
                                                       'makereg', 'map', 'maps', 'maprestart', 'moon', 'password', 'mute', 'kick', 'tempban', 'ban', 'permban',
                                                       'putgroup', 'reload', 'setnextmap', 'shuffleteams', 'swapteams', 'unban', 'ungroup', 'slap']
        # alphabetic sort of the commands
        self.mod_cmds.sort()
        self.admin_cmds.sort()
        self.fulladmin_cmds.sort()
        self.senioradmin_cmds.sort()

        self.config_file = config_file
        config = ConfigParser.ConfigParser()
        config.read(config_file)

        # enable/disable debug output
        verbose = config.getboolean('bot', 'verbose') if config.has_option('bot', 'verbose') else False
        # logging format
        formatter = logging.Formatter('[%(asctime)s] %(levelname)-8s %(message)s', datefmt='%d.%m.%Y %H:%M:%S')
        # console logging
        console = logging.StreamHandler()
        if not verbose:
            console.setLevel(logging.INFO)
        console.setFormatter(formatter)

        # devel.log file
        devel_log = logging.handlers.RotatingFileHandler(filename='devel.log', maxBytes=2097152, backupCount=1, encoding='utf8')
        devel_log.setLevel(logging.INFO)
        devel_log.setFormatter(formatter)

        # add logging handler
        logger.addHandler(console)
        logger.addHandler(devel_log)

        logger.info("*** Spunky Bot v%s : www.spunkybot.de ***", __version__)
        logger.info("Starting logging      : OK")
        logger.info("Loading config file   : %s", config_file)

        games_log = config.get('server', 'log_file')

        self.ffa_lms_gametype = False
        self.ctf_gametype = False
        self.ts_gametype = False
        self.tdm_gametype = False
        self.bomb_gametype = False
        self.freeze_gametype = False
        self.ts_do_team_balance = False
        self.allow_cmd_teams = True
        self.urt_modversion = None
        self.game = None
        self.players_lock = RLock()
        self.firstblood = False
        self.firstnadekill = False
        self.firstknifekill = False

        # enable/disable autokick for team killing
        self.tk_autokick = config.getboolean('bot', 'teamkill_autokick') if config.has_option('bot', 'teamkill_autokick') else True
        # enable/disable autokick of players with low score
        self.noob_autokick = config.getboolean('bot', 'noob_autokick') if config.has_option('bot', 'noob_autokick') else False
        # set the maximum allowed ping
        self.max_ping = config.getint('bot', 'max_ping') if config.has_option('bot', 'max_ping') else 200
        # kick spectator on full server
        self.num_kick_specs = config.getint('bot', 'kick_spec_full_server') if config.has_option('bot', 'kick_spec_full_server') else 10
        # set task frequency
        self.task_frequency = config.getint('bot', 'task_frequency') if config.has_option('bot', 'task_frequency') else 60
        # enable/disable message 'Player connected from...'
        self.show_country_on_connect = config.getboolean('bot', 'show_country_on_connect') if config.has_option('bot', 'show_country_on_connect') else True
        # enable/disable message 'Firstblood / first nade kill...'
        self.show_first_kill_msg = config.getboolean('bot', 'show_first_kill') if config.has_option('bot', 'show_first_kill') else True
        self.show_hit_stats_msg = config.getboolean('bot', 'show_hit_stats_respawn') if config.has_option('bot', 'show_hit_stats_respawn') else True
        # set teams autobalancer
        self.teams_autobalancer = config.getboolean('bot', 'autobalancer') if config.has_option('bot', 'autobalancer') else False
        self.allow_cmd_teams_round_end = config.getboolean('bot', 'allow_teams_round_end') if config.has_option('bot', 'allow_teams_round_end') else False
        self.spam_bomb_planted_msg = config.getboolean('bot', 'spam_bomb_planted') if config.has_option('bot', 'spam_bomb_planted') else True
        self.spam_knife_kills_msg = config.getboolean('bot', 'spam_knife_kills') if config.has_option('bot', 'spam_knife_kills') else False
        self.spam_nade_kills_msg = config.getboolean('bot', 'spam_nade_kills') if config.has_option('bot', 'spam_nade_kills') else False
        self.spam_headshot_hits_msg = config.getboolean('bot', 'spam_headshot_hits') if config.has_option('bot', 'spam_headshot_hits') else False
        # support for low gravity server
        self.support_lowgravity = config.getboolean('lowgrav', 'support_lowgravity') if config.has_option('lowgrav', 'support_lowgravity') else False
        self.gravity = config.getint('lowgrav', 'gravity') if config.has_option('lowgrav', 'gravity') else 800
        logger.info("Configuration loaded  : OK")
        # enable/disable option to get Head Admin by checking existence of head admin in database
        curs.execute("SELECT COUNT(*) FROM `xlrstats` WHERE `admin_role` = 100")
        self.iamgod = True if curs.fetchone()[0] < 1 else False
        logger.info("Connecting to Database: OK")
        logger.debug("Cmd !iamgod available : %s", self.iamgod)
        # Master Server
        self.base_url = 'http://master.spunkybot.de'
        server_port = config.get('server', 'server_port') if config.has_option('server', 'server_port') else "27960"
        # Heartbeat packet
        data = {'v': __version__, 'p': server_port, 'o': platform.platform()}
        values = urllib.urlencode(data)
        self.ping_url = '%s/ping.php?%s' % (self.base_url, values)
        # Rotating Messages and Rules
        if config.getboolean('rules', 'show_rules'):
            rules_frequency = config.getint('rules', 'rules_frequency')
            self.rules_file = os.path.join(HOME, 'conf', 'rules.conf')
            self.rules_frequency = rules_frequency if rules_frequency > 0 else 10
            self.thread_rotate()
            logger.info("Load rotating messages: OK")
        # Parse Game log file
        try:
            # open game log file
            self.log_file = open(games_log, 'r')
        except IOError:
            logger.error("ERROR: The Gamelog file '%s' has not been found", games_log)
            logger.error("*** Aborting Spunky Bot ***")
        else:
            # go to the end of the file
            self.log_file.seek(0, 2)
            # start parsing the games logfile
            logger.info("Parsing Gamelog file  : %s", games_log)
            self.read_log()

    def thread_rotate(self):
        """
        Thread process for starting method rotate_messages
        """
        processor = Thread(target=self.rotating_messages)
        processor.setDaemon(True)
        processor.start()

    def rotating_messages(self):
        """
        display rotating messages and rules
        """
        # initial wait
        time.sleep(30)
        while 1:
            with open(self.rules_file, 'r') as filehandle:
                rotation_msg = filehandle.readlines()
            if not rotation_msg:
                break
            for line in rotation_msg:
                # display rule
                with self.players_lock:
                    if "@admins" in line:
                        self.game.rcon_say(self.get_admins_online())
                    elif "@nextmap" in line:
                        self.game.rcon_say(self.get_nextmap())
                    elif "@time" in line:
                        self.game.rcon_say("^7Time: %s" % time.strftime("%H:%M", time.localtime(time.time())))
                    else:
                        self.game.rcon_say("^2%s" % line.strip())
                # wait for given delay in the config file
                time.sleep(self.rules_frequency)

    def find_game_start(self):
        """
        find InitGame start
        """
        seek_amount = 768
        # search within the specified range for the InitGame message
        start_pos = self.log_file.tell() - seek_amount
        end_pos = start_pos + seek_amount
        try:
            self.log_file.seek(start_pos)
        except IOError:
            logger.error("ERROR: The games.log file is empty, ignoring game type and start")
            # go to the end of the file
            self.log_file.seek(0, 2)
            game_start = True
        else:
            game_start = False
        while not game_start:
            while self.log_file:
                line = self.log_file.readline()
                tmp = line.split()
                if len(tmp) > 1 and tmp[1] == "InitGame:":
                    game_start = True
                    if 'g_modversion\\4.3' in line:
                        self.hit_item.update({23: "UT_MOD_FRF1", 24: "UT_MOD_BENELLI", 25: "UT_MOD_P90",
                                              26: "UT_MOD_MAGNUM", 29: "UT_MOD_KICKED", 30: "UT_MOD_KNIFE_THROWN"})
                        self.death_cause.update({42: "UT_MOD_FRF1", 43: "UT_MOD_BENELLI", 44: "UT_MOD_P90", 45: "UT_MOD_MAGNUM",
                                                 46: "UT_MOD_TOD50", 47: "UT_MOD_FLAG", 48: "UT_MOD_GOOMBA"})
                        self.urt_modversion = 43
                        logger.info("Game modversion       : 4.3")
                    elif 'g_modversion\\4.2' in line:
                        self.hit_item.update({23: "UT_MOD_BLED", 24: "UT_MOD_KICKED", 25: "UT_MOD_KNIFE_THROWN"})
                        self.death_cause.update({42: "UT_MOD_FLAG", 43: "UT_MOD_GOOMBA"})
                        self.urt_modversion = 42
                        logger.info("Game modversion       : 4.2")
                    elif 'g_modversion\\4.1' in line:
                        # hit zone support for UrT 4.1
                        self.hit_points = {0: "HEAD", 1: "HELMET", 2: "TORSO", 3: "KEVLAR", 4: "ARMS", 5: "LEGS", 6: "BODY"}
                        self.hit_item.update({21: "UT_MOD_KICKED", 22: "UT_MOD_KNIFE_THROWN"})
                        self.death_cause.update({33: "UT_MOD_BOMBED", 34: "UT_MOD_NUKED", 35: "UT_MOD_NEGEV",
                                                 39: "UT_MOD_FLAG", 40: "UT_MOD_GOOMBA"})
                        self.urt_modversion = 41
                        logger.info("Game modversion       : 4.1")

                    if 'g_gametype\\0\\' in line or 'g_gametype\\1\\' in line or 'g_gametype\\9\\' in line or 'g_gametype\\11\\' in line:
                        # disable teamkill event and some commands for FFA (0), LMS (1), Jump (9), Gun (11)
                        self.ffa_lms_gametype = True
                    elif 'g_gametype\\7\\' in line:
                        self.ctf_gametype = True
                    elif 'g_gametype\\4\\' in line or 'g_gametype\\5\\' in line:
                        self.ts_gametype = True
                    elif 'g_gametype\\3\\' in line:
                        self.tdm_gametype = True
                    elif 'g_gametype\\8\\' in line:
                        self.bomb_gametype = True
                    elif 'g_gametype\\10\\' in line:
                        self.freeze_gametype = True
                if self.log_file.tell() > end_pos:
                    break
                elif not line:
                    break
            if self.log_file.tell() < seek_amount:
                self.log_file.seek(0, 0)
            else:
                cur_pos = start_pos - seek_amount
                end_pos = start_pos
                start_pos = cur_pos
                if start_pos < 0:
                    start_pos = 0
                self.log_file.seek(start_pos)

    def read_log(self):
        """
        read the logfile
        """
        if self.task_frequency > 0:
            # schedule the task
            if self.task_frequency < 10:
                # avoid flooding with too less delay
                schedule.every(10).seconds.do(self.taskmanager)
            else:
                schedule.every(self.task_frequency).seconds.do(self.taskmanager)
        # schedule the task
        schedule.every(12).hours.do(self.send_heartbeat)
        # schedule the task
        schedule.every(2).hours.do(self.remove_expired_db_entries)

        self.find_game_start()

        # create instance of Game
        self.game = Game(self.config_file, self.urt_modversion)

        self.log_file.seek(0, 2)
        while self.log_file:
            schedule.run_pending()
            line = self.log_file.readline()
            if line:
                self.parse_line(line)
            else:
                if not self.game.live:
                    self.game.go_live()
                time.sleep(.125)

    def send_heartbeat(self):
        """
        send heartbeat packet
        """
        try:
            urllib2.urlopen(self.ping_url)
        except urllib2.URLError:
            pass

    def remove_expired_db_entries(self):
        """
        delete expired ban points
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
        values = (timestamp,)
        # remove expired ban_points
        curs.execute("DELETE FROM `ban_points` WHERE `expires` < ?", values)
        conn.commit()

    def taskmanager(self):
        """
        - check warnings and kick players with too many warnings
        - check for spectators and set warning
        - check for players with low score and set warning
        """
        try:
            # get rcon status
            self.game.send_rcon('status')
            with self.players_lock:
                # get number of connected players
                counter = len(self.game.players) - 1  # bot is counted as player

                # check amount of warnings and kick player if needed
                for player in self.game.players.itervalues():
                    player_num = player.get_player_num()
                    if player_num == BOT_PLAYER_NUM:
                        continue
                    player_name = player.get_name()
                    player_admin_role = player.get_admin_role()

                    # kick player with 3 or more warnings, Admins will never get kicked
                    if player.get_warning() > 2 and player_admin_role < 40:
                        if 'spectator' in player.get_last_warn_msg():
                            kick_msg = reason = "spectator too long on full server"
                        elif 'ping' in player.get_last_warn_msg():
                            kick_msg = "ping too high for this server ^7[^4%s^7]" % player.get_ping_value()
                            reason = "fix your ping"
                        elif 'score' in player.get_last_warn_msg():
                            kick_msg = reason = "score too low for this server"
                        else:
                            kick_msg = reason = "too many warnings"
                        self.game.rcon_say("^2%s ^7was kicked, %s" % (player_name, kick_msg))
                        self.game.kick_player(player_num, reason=reason)
                        continue

                    # check for spectators and set warning
                    if self.num_kick_specs > 0 and player_admin_role < 20:
                        # ignore player with name prefix GTV-
                        if 'GTV-' in player_name:
                            continue
                        # if player is spectator on full server, inform player and increase warn counter
                        # GTV or Moderator or higher levels will not get the warning
                        elif counter > self.num_kick_specs and player.get_team() == 3 and player.get_time_joined() < (time.time() - 30):
                            player.add_warning(warning='spectator too long on full server', timer=False)
                            logger.debug("%s is spectator too long on full server", player_name)
                            warnmsg = "^1WARNING ^7[^3%d^7]: ^7You are spectator too long on full server" % player.get_warning()
                            self.game.rcon_tell(player_num, warnmsg, False)
                        # reset spec warning
                        else:
                            player.clear_specific_warning('spectator too long on full server')

                    # check for players with low score and set warning
                    if self.noob_autokick and player_admin_role < 2:
                        kills = player.get_kills()
                        deaths = player.get_deaths()
                        ratio = round(float(kills) / float(deaths), 2) if deaths > 0 else 1.0
                        # if player ratio is too low, inform player and increase warn counter
                        # Regulars or higher levels will not get the warning
                        if kills > 0 and ratio < 0.33:
                            player.add_warning(warning='score too low for this server', timer=False)
                            logger.debug("Score of %s is too low, ratio: %s", player_name, ratio)
                            warnmsg = "^1WARNING ^7[^3%d^7]: ^7Your score is too low for this server" % player.get_warning()
                            self.game.rcon_tell(player_num, warnmsg, False)
                        else:
                            player.clear_specific_warning('score too low for this server')

                    # warn player with 3 warnings, Admins will never get the alert warning
                    if player.get_warning() == 3 and player_admin_role < 40:
                        self.game.rcon_say("^1ALERT: ^2%s ^7auto-kick from warnings if not cleared" % player_name)

                # check for player with high ping
                self.check_player_ping()

        except Exception as err:
            logger.error(err, exc_info=True)

    def check_player_ping(self):
        """
        check ping of all players and set warning for high ping user
        """
        if self.max_ping > 0:
            # rcon update status
            self.game.quake.rcon_update()
            for player in self.game.quake.players:
                # if ping is too high, increase warn counter, Admins or higher levels will not get the warning
                try:
                    ping_value = player.ping
                    gameplayer = self.game.players[player.num]
                except KeyError:
                    continue
                else:
                    if self.max_ping < ping_value < 999 and gameplayer.get_admin_role() < 40:
                        gameplayer.add_high_ping(ping_value)
                        self.game.rcon_tell(player.num, "^1WARNING ^7[^3%d^7]: ^7Your ping is too high [^4%d^7]. ^3The maximum allowed ping is %d." % (gameplayer.get_warning(), ping_value, self.max_ping), False)
                    else:
                        gameplayer.clear_specific_warning('fix your ping')

    def parse_line(self, string):
        """
        parse the logfile and search for specific action
        """
        line = string[7:]
        tmp = line.split(":", 1)
        line = tmp[1].strip() if len(tmp) > 1 else tmp[0].strip()
        option = {'InitGame': self.new_game, 'Warmup': self.handle_warmup, 'InitRound': self.handle_initround,
                  'Exit': self.handle_exit, 'say': self.handle_say, 'saytell': self.handle_saytell,
                  'ClientUserinfo': self.handle_userinfo, 'ClientUserinfoChanged': self.handle_userinfo_changed,
                  'ClientBegin': self.handle_begin, 'ClientDisconnect': self.handle_disconnect,
                  'SurvivorWinner': self.handle_teams_ts_mode, 'Kill': self.handle_kill, 'Hit': self.handle_hit,
                  'Freeze': self.handle_freeze, 'ThawOutFinished': self.handle_thawout,
                  'Flag': self.handle_flag, 'FlagCaptureTime': self.handle_flagcapturetime}

        try:
            action = tmp[0].strip()
            if action in option:
                option[action](line)
            elif 'Bomb' in action:
                self.handle_bomb(line)
            elif 'Pop' in action:
                self.handle_bomb_exploded()
        except (IndexError, KeyError):
            pass
        except Exception as err:
            logger.error(err, exc_info=True)

    def explode_line(self, line):
        """
        explode line
        """
        arr = line.lstrip().lstrip('\\').split('\\')
        key = True
        key_val = None
        values = {}
        for item in arr:
            if key:
                key_val = item
                key = False
            else:
                values[key_val.rstrip()] = item.rstrip()
                key_val = None
                key = True
        return values

    def new_game(self, line):
        """
        set-up a new game
        """
        self.ffa_lms_gametype = True if ('g_gametype\\0\\' in line or 'g_gametype\\1\\' in line or 'g_gametype\\9\\' in line or 'g_gametype\\11\\' in line) else False
        self.ctf_gametype = True if 'g_gametype\\7\\' in line else False
        self.ts_gametype = True if ('g_gametype\\4\\' in line or 'g_gametype\\5\\' in line) else False
        self.tdm_gametype = True if 'g_gametype\\3\\' in line else False
        self.bomb_gametype = True if 'g_gametype\\8\\' in line else False
        self.freeze_gametype = True if 'g_gametype\\10\\' in line else False
        logger.debug("InitGame: Starting game...")
        self.game.rcon_clear()
        # reset the player stats
        self.stats_reset()

        # set the current map
        self.game.set_current_map()
        # load all available maps
        self.game.set_all_maps()

        # support for low gravity server
        if self.support_lowgravity:
            self.game.send_rcon("set g_gravity %d" % self.gravity)

    def handle_flagcapturetime(self, line):
        """
        handle flag capture time
        """
        tmp = line.split(": ", 1)
        player_num = int(tmp[0])
        action = tmp[1]
        if action.isdigit():
            cap_time = round(float(action) / 1000, 2)
            logger.debug("Player %d captured the flag in %s seconds", player_num, cap_time)
            with self.players_lock:
                self.game.players[player_num].set_flag_capture_time(cap_time)

    def handle_warmup(self, line):
        """
        handle warmup
        """
        logger.debug("Warmup... %s", line)
        self.allow_cmd_teams = True

    def handle_initround(self, _):
        """
        handle Init Round
        """
        logger.debug("InitRound: Round started...")
        if self.ctf_gametype:
            with self.players_lock:
                for player in self.game.players.itervalues():
                    player.reset_flag_stats()
        elif self.ts_gametype or self.bomb_gametype or self.freeze_gametype:
            if self.allow_cmd_teams_round_end:
                self.allow_cmd_teams = False

    def handle_exit(self, line):
        """
        handle Exit of a match, show Awards, store user score in database and reset statistics
        """
        logger.debug("Exit: %s", line)
        self.handle_awards()
        self.allow_cmd_teams = True
        self.stats_reset(store_score=True)

    def stats_reset(self, store_score=False):
        """
        store user score in database if needed and reset the player statistics
        """
        with self.players_lock:
            for player in self.game.players.itervalues():
                if store_score:
                    # store score in database
                    player.save_info()
                # reset player statistics
                player.reset()
                # reset team lock
                player.set_team_lock(None)

        # set first kill trigger
        if self.show_first_kill_msg and not self.ffa_lms_gametype:
            self.firstblood = True
            self.firstnadekill = True
            self.firstknifekill = True
        else:
            self.firstblood = False
            self.firstnadekill = False
            self.firstknifekill = False

    def handle_userinfo(self, line):
        """
        handle player user information, auto-kick known cheater ports or guids
        """
        with self.players_lock:
            player_num = int(line[:2].strip())
            line = line[2:].lstrip("\\").lstrip()
            values = self.explode_line(line)
            challenge = True if 'challenge' in values else False
            name = values['name'].replace(' ', '') if 'name' in values else "UnnamedPlayer"
            ip_port = values['ip'] if 'ip' in values else "0.0.0.0:0"
            auth = values['authl'] if 'authl' in values else ""
            if 'cl_guid' in values:
                guid = values['cl_guid']
            elif 'skill' in values:
                # bot connecting
                guid = "BOT%d" % player_num
            else:
                guid = "None"
                self.kick_player_reason(reason="Player with invalid GUID kicked", player_num=player_num)

            ip_address = ip_port.split(":")[0].strip()
            port = ip_port.split(":")[1].strip()

            if player_num not in self.game.players:
                player = Player(player_num, ip_address, guid, name, auth)
                self.game.add_player(player)
                # kick banned player
                player_ban_id = self.game.players[player_num].get_ban_id()
                if player_ban_id:
                    self.kick_player_reason("^7%s ^1banned ^7(ID @%d)" % (name, player_ban_id), player_num)
                else:
                    if self.show_country_on_connect:
                        self.game.rcon_say("^7%s ^7connected from %s" % (name, self.game.players[player_num].get_country()))

            if self.game.players[player_num].get_guid() != guid:
                self.game.players[player_num].set_guid(guid)
            if self.game.players[player_num].get_name() != name:
                self.game.players[player_num].set_name(name)

            # kick player with hax guid 'kemfew'
            if "KEMFEW" in guid.upper():
                self.kick_player_reason("Cheater GUID detected for %s -> Player kicked" % name, player_num)
            if "WORLD" in guid.upper() or "UNKNOWN" in guid.upper():
                self.kick_player_reason("Invalid GUID detected for %s -> Player kicked" % name, player_num)

            if challenge:
                logger.debug("ClientUserinfo: Player %d %s is challenging the server and has the guid %s", player_num, name, guid)
                # kick player with hax port 1337 or 1024
                if port == "1337":  # or port == "1024":
                    self.kick_player_reason("Cheater Port detected for %s -> Player kicked" % name, player_num)

    def kick_player_reason(self, reason, player_num):
        """
        kick player for specific reason
        """
        self.game.send_rcon("kick %d" % player_num)
        self.game.send_rcon(reason)

    def handle_userinfo_changed(self, line):
        """
        handle player changes
        """
        with self.players_lock:
            player_num = int(line[:2].strip())
            player = self.game.players[player_num]
            line = line[2:].lstrip("\\")
            try:
                values = self.explode_line(line)
                team_num = int(values['t'])
                player.set_team(team_num)
                name = values['n'].replace(' ', '')
            except KeyError:
                team_num = 3
                player.set_team(team_num)
                name = self.game.players[player_num].get_name()

            # set new name, if player changed name
            if not self.game.players[player_num].get_name() == name:
                self.game.players[player_num].set_name(name)

            # move locked player to the defined team, if player tries to change teams
            team_lock = self.game.players[player_num].get_team_lock()
            if team_lock and Player.teams[team_num] != team_lock:
                self.game.rcon_forceteam(player_num, team_lock)
                self.game.rcon_tell(player_num, "^3You are forced to: ^7%s" % team_lock)
            logger.debug("ClientUserinfoChanged: Player %d %s joined team %s", player_num, name, Player.teams[team_num])

    def handle_begin(self, line):
        """
        handle player entering game
        """
        with self.players_lock:
            player_num = int(line)
            player = self.game.players[player_num]
            player_name = player.get_name()
            # Welcome message for registered players
            if player.get_registered_user() and player.get_welcome_msg():
                self.game.rcon_tell(player_num, "^7[^2Authed^7] Welcome back %s, you are ^2%s^7, last visit %s, you played %s times" % (player_name, player.roles[player.get_admin_role()], player.get_last_visit(), player.get_num_played()), False)
                # disable welcome message for next rounds
                player.disable_welcome_msg()
            logger.debug("ClientBegin: Player %d %s has entered the game", player_num, player_name)

    def handle_disconnect(self, line):
        """
        handle player disconnect
        """
        with self.players_lock:
            player_num = int(line)
            player = self.game.players[player_num]
            player.save_info()
            player.reset()
            del self.game.players[player_num]
            logger.debug("ClientDisconnect: Player %d %s has left the game", player_num, player.get_name())

    def handle_hit(self, line):
        """
        handle all kind of hits
        """
        with self.players_lock:
            info = line.split(":", 1)[0].split()
            hitter_id = int(info[1])
            victim_id = int(info[0])
            hitter = self.game.players[hitter_id]
            hitter_name = hitter.get_name()
            hitpoint = int(info[2])
            hit_item = int(info[3])
            # increase summary of all hits
            hitter.set_all_hits()

            zones = {'TORSO': 'body', 'VEST': 'body', 'KEVLAR': 'body', 'BUTT': 'body', 'GROIN': 'body',
                     'LEGS': 'legs', 'LEFT_UPPER_LEG': 'legs', 'RIGHT_UPPER_LEG': 'legs',
                     'LEFT_LOWER_LEG': 'legs', 'RIGHT_LOWER_LEG': 'legs', 'LEFT_FOOT': 'legs', 'RIGHT_FOOT': 'legs',
                     'ARMS': 'arms', 'LEFT_ARM': 'arms', 'RIGHT_ARM': 'arms'}

            if hitpoint in self.hit_points:
                if self.hit_points[hitpoint] == 'HEAD' or self.hit_points[hitpoint] == 'HELMET':
                    hitter.headshot()
                    hitter_hs_count = hitter.get_headshots()
                    hs_msg = {5: 'watch out!',
                              10: 'awesome!',
                              15: 'unbelievable!',
                              20: '^1MANIAC!',
                              25: '^2AIMBOT?',
                              30: 'stop that'}
                    if self.spam_headshot_hits_msg and hitter_hs_count in hs_msg:
                        self.game.rcon_bigtext("^3%s: ^2%d ^7HeadShots, %s" % (hitter_name, hitter_hs_count, hs_msg[hitter_hs_count]))
                    hs_plural = "headshots" if hitter_hs_count > 1 else "headshot"
                    percentage = int(round(float(hitter_hs_count) / float(hitter.get_all_hits()), 2) * 100)
                    self.game.send_rcon("^7%s has ^2%d ^7%s (%d percent)" % (hitter_name, hitter_hs_count, hs_plural, percentage))
                elif self.hit_points[hitpoint] in zones:
                    hitter.set_hitzones(zones[self.hit_points[hitpoint]])
                logger.debug("Player %d %s hit %d %s in the %s with %s", hitter_id, hitter_name, victim_id, self.game.players[victim_id].get_name(), self.hit_points[hitpoint], self.hit_item[hit_item])

    def handle_kill(self, line):
        """
        handle kills
        """
        with self.players_lock:
            parts = line.split(":", 1)
            info = parts[0].split()
            k_name = parts[1].split()[0]
            killer_id = int(info[0])
            victim_id = int(info[1])
            death_cause = self.death_cause[int(info[2])]
            victim = self.game.players[victim_id]

            if k_name == "<non-client>":
                # killed by World
                killer_id = BOT_PLAYER_NUM
            killer = self.game.players[killer_id]

            killer_name = killer.get_name()
            victim_name = victim.get_name()
            tk_event = False

            # teamkill event - disabled for FFA, LMS, Jump, for all other game modes team kills are counted and punished
            if not self.ffa_lms_gametype:
                if (victim.get_team() == killer.get_team() and victim_id != killer_id) and death_cause != "UT_MOD_BOMBED":
                    tk_event = True
                    # increase team kill counter for killer and kick for too many team kills
                    killer.team_kill()
                    # increase team death counter for victim
                    victim.team_death()
                    # Regular and higher will not get punished
                    if killer.get_admin_role() < 2 and self.tk_autokick:
                        # list of players of TK victim
                        killer.add_tk_victims(victim_id)
                        # list of players who killed victim
                        victim.add_killed_me(killer_id)
                        self.game.rcon_tell(killer_id, "^7Do not attack teammates, you ^1killed ^7%s" % victim_name)
                        self.game.rcon_tell(victim_id, "^7Type ^3!fp ^7to forgive ^3%s" % killer_name)
                        if len(killer.get_tk_victim_names()) >= 5:
                            # add TK ban points - 15 minutes
                            duration = killer.add_ban_point('tk, auto-kick', 900)
                            if duration > 0:
                                self.game.rcon_say("^3%s ^7banned for ^1%d minutes ^7for team killing" % (killer_name, duration))
                            else:
                                self.game.rcon_say("^7Player ^2%s ^7kicked for team killing" % killer_name)
                            self.game.kick_player(killer_id, reason='stop team killing')
                        elif len(killer.get_tk_victim_names()) == 2:
                            self.game.rcon_tell(killer_id, "^1WARNING ^7[^31^7]: ^7For team killing you will get kicked", False)
                        elif len(killer.get_tk_victim_names()) == 3:
                            self.game.rcon_tell(killer_id, "^1WARNING ^7[^32^7]: ^7For team killing you will get kicked", False)
                        elif len(killer.get_tk_victim_names()) == 4:
                            self.game.rcon_tell(killer_id, "^1WARNING ^7[^33^7]: ^7For team killing you will get kicked", False)

            suicide_reason = ['UT_MOD_SUICIDE', 'MOD_FALLING', 'MOD_WATER', 'MOD_LAVA', 'MOD_TRIGGER_HURT',
                              'UT_MOD_SPLODED', 'UT_MOD_SLAPPED', 'UT_MOD_SMITED']
            suicide_weapon = ['UT_MOD_HEGRENADE', 'UT_MOD_HK69', 'UT_MOD_NUKED', 'UT_MOD_BOMBED']
            # suicide counter
            if death_cause in suicide_reason or (killer_id == victim_id and death_cause in suicide_weapon):
                victim.suicide()
                victim.die()
                logger.debug("Player %d %s committed suicide with %s", victim_id, victim_name, death_cause)
            # kill counter
            elif not tk_event and int(info[2]) != 10:  # 10: MOD_CHANGE_TEAM
                killer.kill()

                # first kill message
                if self.firstblood:
                    self.game.rcon_bigtext("^1FIRSTBLOOD: ^7%s killed by ^3%s" % (victim_name, killer_name))
                    self.firstblood = False
                    if death_cause == 'UT_MOD_HEGRENADE':
                        self.firstnadekill = False
                    if death_cause == 'UT_MOD_KNIFE' or death_cause == 'UT_MOD_KNIFE_THROWN':
                        self.firstknifekill = False
                elif self.firstnadekill and death_cause == 'UT_MOD_HEGRENADE':
                    self.game.rcon_bigtext("^3%s: ^7first HE grenade kill" % killer_name)
                    self.firstnadekill = False
                elif self.firstknifekill and (death_cause == 'UT_MOD_KNIFE' or death_cause == 'UT_MOD_KNIFE_THROWN'):
                    self.game.rcon_bigtext("^3%s: ^7first knife kill" % killer_name)
                    self.firstknifekill = False

                # bomb mode
                if self.bomb_gametype:
                    # bomb carrier killed
                    if victim.get_bombholder():
                        killer.kill_bomb_carrier()
                    # killed with bomb
                    if death_cause == 'UT_MOD_BOMBED':
                        killer.kills_with_bomb()

                event_series_msg = {5: 'go on!',
                                    10: 'beware!',
                                    15: 'eat that!',
                                    20: 'got pwned!'}

                # HE grenade kill
                if death_cause == 'UT_MOD_HEGRENADE':
                    killer.set_he_kill()
                    he_kill_count = killer.get_he_kills()
                    if self.spam_nade_kills_msg and he_kill_count in event_series_msg:
                        self.game.rcon_bigtext("^3%s: ^2%d ^7HE grenade kills, %s" % (killer_name, he_kill_count, event_series_msg[he_kill_count]))

                # Knife kill
                if "UT_MOD_KNIFE" in death_cause or "UT_MOD_KNIFE_THROWN" in death_cause:
                    killer.set_knife_kill()
                    knife_kill_count = killer.get_knife_kills()
                    if self.spam_knife_kills_msg and knife_kill_count in event_series_msg:
                        self.game.rcon_bigtext("^3%s: ^2%d ^7knife kills, %s" % (killer_name, knife_kill_count, event_series_msg[knife_kill_count]))

                # killing spree counter
                killer_color = "^1" if (killer.get_team() == 1) else "^4"
                killer_killing_streak = killer.get_killing_streak()
                kill_streak_msg = {5: "is on a killing spree (^15 ^7kills in a row)",
                                   10: "is on a rampage (^110 ^7kills in a row)",
                                   15: "is unstoppable (^115 ^7kills in a row)",
                                   20: "is godlike (^120 ^7kills in a row)"}
                if killer_killing_streak in kill_streak_msg and killer_id != BOT_PLAYER_NUM:
                    self.game.rcon_say("%s%s ^7%s" % (killer_color, killer_name, kill_streak_msg[killer_killing_streak]))

                victim_color = "^1" if (victim.get_team() == 1) else "^4"
                if victim.get_killing_streak() >= 20 and killer_name != victim_name and killer_id != BOT_PLAYER_NUM:
                    self.game.rcon_say("%s%s's ^7godlike was ended by %s%s!" % (victim_color, victim_name, killer_color, killer_name))
                elif victim.get_killing_streak() >= 15 and killer_name != victim_name and killer_id != BOT_PLAYER_NUM:
                    self.game.rcon_say("%s%s's ^7unstoppable was ended by %s%s!" % (victim_color, victim_name, killer_color, killer_name))
                elif victim.get_killing_streak() >= 10 and killer_name != victim_name and killer_id != BOT_PLAYER_NUM:
                    self.game.rcon_say("%s%s's ^7rampage was ended by %s%s!" % (victim_color, victim_name, killer_color, killer_name))
                elif victim.get_killing_streak() >= 5 and killer_name != victim_name and killer_id != BOT_PLAYER_NUM:
                    self.game.rcon_say("%s%s's ^7killing spree was ended by %s%s!" % (victim_color, victim_name, killer_color, killer_name))

                # death counter
                victim.die()
                if self.show_hit_stats_msg:
                    self.game.rcon_tell(victim_id, "^1HIT Stats: ^7HS: ^2%s ^7BODY: ^2%s ^7ARMS: ^2%s ^7LEGS: ^2%s ^7TOTAL: ^2%s" % (victim.get_headshots(), victim.get_hitzones('body'), victim.get_hitzones('arms'), victim.get_hitzones('legs'), victim.get_all_hits()))
                logger.debug("Player %d %s killed %d %s with %s", killer_id, killer_name, victim_id, victim_name, death_cause)

    def player_found(self, user):
        """
        return True and instance of player or False and message text
        """
        victim = None
        name_list = []
        append = name_list.append
        for player in self.game.players.itervalues():
            player_num = player.get_player_num()
            if player_num == BOT_PLAYER_NUM:
                continue
            player_name = player.get_name()
            player_authname = player.get_authname()
            player_id = "@%d" % player.get_player_id()
            if user.upper() == player_name.upper() or user == str(player_num) or user == player_id or user.lower() == player_authname:
                victim = player
                name_list = ["^3%s [^2%d^3]" % (player_name, player_num)]
                break
            elif user.upper() in player_name.upper():
                victim = player
                append("^3%s [^2%d^3]" % (player_name, player_num))
        if not name_list:
            if user.startswith('@'):
                return self.offline_player(user)
            else:
                return False, None, "^3No players found matching %s" % user
        elif len(name_list) > 1:
            return False, None, "^7Players matching %s: ^3%s" % (user, ', '.join(name_list))
        else:
            return True, victim, "^7Found player matching %s: ^3%s" % (user, name_list[-1])

    def offline_player(self, user_id):
        """
        return True and instance of player or False and message text
        """
        player_id = user_id.lstrip('@')
        if player_id.isdigit():
            if int(player_id) > 1:
                values = (player_id,)
                curs.execute("SELECT `guid`,`name`,`ip_address` FROM `player` WHERE `id` = ?", values)
                result = curs.fetchone()
                if result:
                    victim = Player(player_num=1023, ip_address=str(result[2]), guid=str(result[0]), name=str(result[1]))
                    victim.define_offline_player(player_id=int(player_id))
                    return True, victim, None
                else:
                    return False, None, "^3No Player found"
            else:
                return False, None, "^3No Player found"
        else:
            return False, None, "^3No Player found"

    def map_found(self, map_name):
        """
        return True and map name or False and message text
        """
        map_list = []
        append = map_list.append
        for maps in self.game.get_all_maps():
            if map_name.lower() == maps or ('ut4_%s' % map_name.lower()) == maps:
                append(maps)
                break
            elif map_name.lower() in maps:
                append(maps)
        if not map_list:
            return False, None, "^3Map not found"
        elif len(map_list) > 1:
            return False, None, "^7Maps matching %s: ^3%s" % (map_name, ', '.join(map_list))
        else:
            return True, map_list[0], None

    def handle_saytell(self, line):
        """
        handle saytell commands
        """
        tmp = line.strip()
        try:
            new = "%s%s" % (tmp[0], ''.join(tmp[1:]))
            self.handle_say(new)
        except IndexError:
            pass

    def clean_cmd_list(self, cmd_list):
        """
        remove commands which are not available in current game type or modversion
        """
        disabled_cmds = []
        clean_list = list(cmd_list)
        if self.ffa_lms_gametype or self.ts_gametype or self.tdm_gametype:
            disabled_cmds = ['bombstats', 'ctfstats', 'freezestats']
        elif self.bomb_gametype:
            disabled_cmds = ['ctfstats', 'freezestats']
        elif self.ctf_gametype:
            disabled_cmds = ['bombstats', 'freezestats']
        elif self.freeze_gametype:
            disabled_cmds = ['bombstats', 'ctfstats']

        if self.urt_modversion == 41:
            disabled_cmds += ['kill']

        for item in disabled_cmds:
            try:
                clean_list.remove(item)
            except ValueError:
                pass
        return clean_list

    def handle_say(self, line):
        """
        handle say commands
        """
        reason_dict = {'obj': 'go for objective',
                       'camp': 'stop camping',
                       'spam': 'do not spam, shut-up!',
                       'lang': 'bad language',
                       'racism': 'racism is not tolerated',
                       'ping': 'fix your ping',
                       'afk': 'away from keyboard',
                       'tk': 'stop team killing',
                       'spec': 'spectator too long on full server',
                       'ci': 'connection interrupted',
                       'whiner': 'stop complaining about camp, lag or block',
                       'skill': 'skill too low for this server',
                       'name': 'do not use offensive names'}

        poke_options = ['Go', 'Wake up', '*poke*', 'Attention', 'Get up', 'Move out']

        with self.players_lock:
            line = line.strip()
            try:
                divider = line.split(": ", 1)
                number = divider[0].split(" ", 1)[0]
                cmd = divider[1].split()[0]

                sar = {'player_num': int(number), 'command': cmd}
            except IndexError:
                sar = {'player_num': BOT_PLAYER_NUM, 'command': ''}

            if sar['command'] == '!mapstats':
                self.game.rcon_tell(sar['player_num'], "^2%d ^7kills - ^2%d ^7deaths" % (self.game.players[sar['player_num']].get_kills(), self.game.players[sar['player_num']].get_deaths()))
                self.game.rcon_tell(sar['player_num'], "^2%d ^7kills in a row - ^2%d ^7teamkills" % (self.game.players[sar['player_num']].get_killing_streak(), self.game.players[sar['player_num']].get_team_kill_count()))
                self.game.rcon_tell(sar['player_num'], "^2%d ^7total hits - ^2%d ^7headshots" % (self.game.players[sar['player_num']].get_all_hits(), self.game.players[sar['player_num']].get_headshots()))
                self.game.rcon_tell(sar['player_num'], "^2%d ^7HE grenade kills" % self.game.players[sar['player_num']].get_he_kills())
                if self.ctf_gametype:
                    if self.urt_modversion > 41:
                        self.game.rcon_tell(sar['player_num'], "^7flags captured: ^2%d ^7- flags returned: ^2%d ^7- fastest cap: ^2%s ^7sec" % (self.game.players[sar['player_num']].get_flags_captured(), self.game.players[sar['player_num']].get_flags_returned(), self.game.players[sar['player_num']].get_flag_capture_time()))
                    else:
                        self.game.rcon_tell(sar['player_num'], "^7flags captured: ^2%d ^7- flags returned: ^2%d" % (self.game.players[sar['player_num']].get_flags_captured(), self.game.players[sar['player_num']].get_flags_returned()))
                elif self.bomb_gametype:
                    self.game.rcon_tell(sar['player_num'], "^7planted: ^2%d ^7- defused: ^2%d" % (self.game.players[sar['player_num']].get_planted_bomb(), self.game.players[sar['player_num']].get_defused_bomb()))
                    self.game.rcon_tell(sar['player_num'], "^7bomb carrier killed: ^2%d ^7- enemies bombed: ^2%d" % (self.game.players[sar['player_num']].get_bomb_carrier_kills(), self.game.players[sar['player_num']].get_kills_with_bomb()))
                elif self.freeze_gametype:
                    self.game.rcon_tell(sar['player_num'], "^7freeze: ^2%d ^7- thaw out: ^2%d" % (self.game.players[sar['player_num']].get_freeze(), self.game.players[sar['player_num']].get_thawout()))

            elif sar['command'] == '!help' or sar['command'] == '!h':
                ## TO DO - specific help for each command
                if self.game.players[sar['player_num']].get_admin_role() < 20:
                    self.game.rcon_tell(sar['player_num'], "^7Available commands: ^3%s" % ', ^3'.join(self.clean_cmd_list(self.user_cmds)))
                # help for mods - additional commands
                elif self.game.players[sar['player_num']].get_admin_role() == 20:
                    self.game.rcon_tell(sar['player_num'], "^7Moderator commands: ^3%s" % ', ^3'.join(self.clean_cmd_list(self.mod_cmds)))
                # help for admins - additional commands
                elif self.game.players[sar['player_num']].get_admin_role() == 40:
                    self.game.rcon_tell(sar['player_num'], "^7Admin commands: ^3%s" % ', ^3'.join(self.clean_cmd_list(self.admin_cmds)))
                elif self.game.players[sar['player_num']].get_admin_role() == 60:
                    self.game.rcon_tell(sar['player_num'], "^7Full Admin commands: ^3%s" % ', ^3'.join(self.clean_cmd_list(self.fulladmin_cmds)))
                elif self.game.players[sar['player_num']].get_admin_role() >= 80:
                    self.game.rcon_tell(sar['player_num'], "^7Senior Admin commands: ^3%s" % ', ^3'.join(self.clean_cmd_list(self.senioradmin_cmds)))

## player commands
            # register - register yourself as a basic user
            elif sar['command'] == '!register':
                if not self.game.players[sar['player_num']].get_registered_user():
                    self.game.players[sar['player_num']].register_user_db(role=1)
                    self.game.rcon_tell(sar['player_num'], "^3%s ^7put in group User" % self.game.players[sar['player_num']].get_name())
                else:
                    self.game.rcon_tell(sar['player_num'], "^3%s ^7is already in a higher level group" % self.game.players[sar['player_num']].get_name())

            # regtest - display current user status
            elif sar['command'] == '!regtest':
                if self.game.players[sar['player_num']].get_registered_user():
                    self.game.rcon_tell(sar['player_num'], "^7%s [^3@%s^7] is registered since ^3%s" % (self.game.players[sar['player_num']].get_name(), self.game.players[sar['player_num']].get_player_id(), self.game.players[sar['player_num']].get_first_seen_date()))
                else:
                    self.game.rcon_tell(sar['player_num'], "^7You are not a registered user.")

            # hs - display headshot counter
            elif sar['command'] == '!hs':
                hs_count = self.game.players[sar['player_num']].get_headshots()
                if hs_count > 0:
                    self.game.rcon_tell(sar['player_num'], "^7You made ^2%d ^7headshot%s" % (hs_count, 's' if hs_count > 1 else ''))
                else:
                    self.game.rcon_tell(sar['player_num'], "^7You made no headshot")

            # spree - display kill streak counter
            elif sar['command'] == '!spree':
                spree_count = self.game.players[sar['player_num']].get_killing_streak()
                if spree_count > 0:
                    self.game.rcon_tell(sar['player_num'], "^7You have ^2%d ^7kill%s in a row" % (spree_count, 's' if spree_count > 1 else ''))
                else:
                    self.game.rcon_tell(sar['player_num'], "^7You are currently not having a killing spree")

            # hestats - display HE grenade kill counter
            elif sar['command'] == '!hestats':
                he_kill_count = self.game.players[sar['player_num']].get_he_kills()
                if he_kill_count > 0:
                    self.game.rcon_tell(sar['player_num'], "^7You made ^2%d ^7HE grenade kill%s" % (he_kill_count, 's' if he_kill_count > 1 else ''))
                else:
                    self.game.rcon_tell(sar['player_num'], "^7You made no HE grenade kill")

            # knife - display knife kill counter
            elif sar['command'] == '!knife':
                knife_kill_count = self.game.players[sar['player_num']].get_knife_kills()
                if knife_kill_count > 0:
                    self.game.rcon_tell(sar['player_num'], "^7You made ^2%d ^7knife kill%s" % (knife_kill_count, 's' if knife_kill_count > 1 else ''))
                else:
                    self.game.rcon_tell(sar['player_num'], "^7You made no knife kill")

            # hits - display hit stats
            elif sar['command'] == '!hits':
                self.game.rcon_tell(sar['player_num'], "^1HIT Stats: ^7HS: ^2%s ^7BODY: ^2%s ^7ARMS: ^2%s ^7LEGS: ^2%s ^7TOTAL: ^2%s" % (self.game.players[sar['player_num']].get_headshots(), self.game.players[sar['player_num']].get_hitzones('body'), self.game.players[sar['player_num']].get_hitzones('arms'), self.game.players[sar['player_num']].get_hitzones('legs'), self.game.players[sar['player_num']].get_all_hits()))

            # bombstats - display bomb statistics
            elif sar['command'] == '!bombstats':
                if self.bomb_gametype:
                    self.game.rcon_tell(sar['player_num'], "^7planted: ^2%d ^7- defused: ^2%d" % (self.game.players[sar['player_num']].get_planted_bomb(), self.game.players[sar['player_num']].get_defused_bomb()))
                    self.game.rcon_tell(sar['player_num'], "^7bomb carrier killed: ^2%d ^7- enemies bombed: ^2%d" % (self.game.players[sar['player_num']].get_bomb_carrier_kills(), self.game.players[sar['player_num']].get_kills_with_bomb()))
                else:
                    self.game.rcon_tell(sar['player_num'], "^7You are not playing Bomb Mode")

            # ctfstats - display ctf statistics
            elif sar['command'] == '!ctfstats':
                if self.ctf_gametype:
                    if self.urt_modversion > 41:
                        self.game.rcon_tell(sar['player_num'], "^7flags captured: ^2%d ^7- flags returned: ^2%d ^7- fastest cap: ^2%s ^7sec" % (self.game.players[sar['player_num']].get_flags_captured(), self.game.players[sar['player_num']].get_flags_returned(), self.game.players[sar['player_num']].get_flag_capture_time()))
                    else:
                        self.game.rcon_tell(sar['player_num'], "^7flags captured: ^2%d ^7- flags returned: ^2%d" % (self.game.players[sar['player_num']].get_flags_captured(), self.game.players[sar['player_num']].get_flags_returned()))
                else:
                    self.game.rcon_tell(sar['player_num'], "^7You are not playing Capture The Flag")

            # freezestats - display freeze tag statistics
            elif sar['command'] == '!freezestats':
                if self.freeze_gametype:
                    self.game.rcon_tell(sar['player_num'], "^7freeze: ^2%d ^7- thaw out: ^2%d" % (self.game.players[sar['player_num']].get_freeze(), self.game.players[sar['player_num']].get_thawout()))
                else:
                    self.game.rcon_tell(sar['player_num'], "^7You are not playing Freeze Tag")

            # time - display the servers current time
            elif sar['command'] == '!time' or sar['command'] == '@time':
                msg = "^7%s" % time.strftime("%H:%M", time.localtime(time.time()))
                self.tell_say_message(sar, msg)

            # teams - balance teams
            elif sar['command'] == '!teams':
                if not self.ffa_lms_gametype:
                    self.handle_team_balance()

            # stats - display current map stats
            elif sar['command'] == '!stats':
                if not self.freeze_gametype:
                    ratio = round(float(self.game.players[sar['player_num']].get_kills()) / float(self.game.players[sar['player_num']].get_deaths()), 2) if self.game.players[sar['player_num']].get_deaths() > 0 else 1.0
                    self.game.rcon_tell(sar['player_num'], "^7Map Stats %s: ^7K ^2%d ^7D ^3%d ^7TK ^1%d ^7Ratio ^5%s ^7HS ^2%d" % (self.game.players[sar['player_num']].get_name(), self.game.players[sar['player_num']].get_kills(), self.game.players[sar['player_num']].get_deaths(), self.game.players[sar['player_num']].get_team_kill_count(), ratio, self.game.players[sar['player_num']].get_headshots()))
                else:
                    # Freeze Tag
                    self.game.rcon_tell(sar['player_num'], "^7Freeze Stats %s: ^7F ^2%d ^7T ^3%d ^7TK ^1%d ^7HS ^2%d" % (self.game.players[sar['player_num']].get_name(), self.game.players[sar['player_num']].get_freeze(), self.game.players[sar['player_num']].get_thawout(), self.game.players[sar['player_num']].get_team_kill_count(), self.game.players[sar['player_num']].get_headshots()))

            # xlrstats - display full player stats
            elif sar['command'] == '!xlrstats':
                if line.split(sar['command'])[1]:
                    arg = line.split(sar['command'])[1].strip()
                    player_found = False
                    for player in self.game.players.itervalues():
                        if (arg.upper() in (player.get_name()).upper()) or arg == str(player.get_player_num()):
                            player_found = True
                            if player.get_registered_user():
                                ratio = round(float(player.get_db_kills()) / float(player.get_db_deaths()), 2) if player.get_db_deaths() > 0 else 1.0
                                self.game.rcon_tell(sar['player_num'], "^7Stats %s: ^7K ^2%d ^7D ^3%d ^7TK ^1%d ^7Ratio ^5%s ^7HS ^2%d" % (player.get_name(), player.get_db_kills(), player.get_db_deaths(), player.get_db_tks(), ratio, player.get_db_headshots()))
                            else:
                                self.game.rcon_tell(sar['player_num'], "^7Sorry, this player is not registered")
                            break
                    if not player_found:
                        self.game.rcon_tell(sar['player_num'], "^7No player found matching ^3%s" % arg)
                else:
                    if self.game.players[sar['player_num']].get_registered_user():
                        ratio = round(float(self.game.players[sar['player_num']].get_db_kills()) / float(self.game.players[sar['player_num']].get_db_deaths()), 2) if self.game.players[sar['player_num']].get_db_deaths() > 0 else 1.0
                        self.game.rcon_tell(sar['player_num'], "^7Stats %s: ^7K ^2%d ^7D ^3%d ^7TK ^1%d ^7Ratio ^5%s ^7HS ^2%d" % (self.game.players[sar['player_num']].get_name(), self.game.players[sar['player_num']].get_db_kills(), self.game.players[sar['player_num']].get_db_deaths(), self.game.players[sar['player_num']].get_db_tks(), ratio, self.game.players[sar['player_num']].get_db_headshots()))
                    else:
                        self.game.rcon_tell(sar['player_num'], "^7You need to ^2!register ^7first")

            # xlrtopstats
            elif (sar['command'] == '!xlrtopstats' or sar['command'] == '!topstats') and self.game.players[sar['player_num']].get_admin_role() >= 1:
                values = (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime((time.time() - 10368000))),)  # last played within the last 120 days
                result = curs.execute("SELECT name FROM `xlrstats` WHERE (`rounds` > 35 or `kills` > 500) and `last_played` > ? ORDER BY `ratio` DESC LIMIT 3", values).fetchall()
                toplist = ['^1#%s ^7%s' % (index + 1, result[index][0]) for index in xrange(len(result))]
                msg = "^3Top players: %s" % str(", ".join(toplist)) if toplist else "^3Awards still available"
                self.game.rcon_tell(sar['player_num'], msg)

            # forgive last team kill
            elif sar['command'] == '!forgiveprev' or sar['command'] == '!fp' or sar['command'] == '!f':
                victim = self.game.players[sar['player_num']]
                if victim.get_killed_me():
                    forgive_player_num = victim.get_killed_me()[-1]
                    forgive_player = self.game.players[forgive_player_num]
                    victim.clear_tk(forgive_player_num)
                    forgive_player.clear_killed_me(victim.get_player_num())
                    self.game.rcon_say("^7%s has forgiven %s's attack" % (victim.get_name(), forgive_player.get_name()))
                else:
                    self.game.rcon_tell(sar['player_num'], "^3No one to forgive")

            # forgive all team kills
            elif sar['command'] == '!forgiveall' or sar['command'] == '!fa':
                victim = self.game.players[sar['player_num']]
                msg = []
                append = msg.append
                if victim.get_killed_me():
                    all_forgive_player_num_list = victim.get_killed_me()
                    forgive_player_num_list = list(set(all_forgive_player_num_list))
                    victim.clear_all_tk()
                    for forgive_player_num in forgive_player_num_list:
                        forgive_player = self.game.players[forgive_player_num]
                        forgive_player.clear_killed_me(victim.get_player_num())
                        append(forgive_player.get_name())
                if msg:
                    self.game.rcon_say("^7%s has forgiven: %s" % (victim.get_name(), ", ".join(msg)))
                else:
                    self.game.rcon_tell(sar['player_num'], "^3No one to forgive")

## mod level 20
            # admintest - display current admin status
            elif sar['command'] == '!admintest' and self.game.players[sar['player_num']].get_admin_role() >= 20:
                player_admin_role = self.game.players[sar['player_num']].get_admin_role()
                self.game.rcon_tell(sar['player_num'], "^7%s [^3@%s^7] is ^3%s ^7[^2%d^7]" % (self.game.players[sar['player_num']].get_name(), self.game.players[sar['player_num']].get_player_id(), self.game.players[sar['player_num']].roles[player_admin_role], player_admin_role))

            # country / locate
            elif (sar['command'] == '!country' or sar['command'] == '@country' or sar['command'] == '!locate') and self.game.players[sar['player_num']].get_admin_role() >= 20:
                if line.split(sar['command'])[1]:
                    user = line.split(sar['command'])[1].strip()
                    found, victim, msg = self.player_found(user)
                    if not found:
                        self.game.rcon_tell(sar['player_num'], msg)
                    else:
                        msg = "^3%s ^7is connecting from ^3%s" % (victim.get_name(), victim.get_country())
                        self.tell_say_message(sar, msg)
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !country <name>")

            # poke - notify a player that he needs to move
            elif sar['command'] == '!poke' and self.game.players[sar['player_num']].get_admin_role() >= 20:
                if line.split(sar['command'])[1]:
                    user = line.split(sar['command'])[1].strip()
                    found, victim, msg = self.player_found(user)
                    if not found:
                        self.game.rcon_tell(sar['player_num'], msg)
                    else:
                        self.game.rcon_tell(sar['player_num'], "^7%s %s!" % (random.choice(poke_options), victim.get_name()))
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !poke <name>")

            # leveltest
            elif (sar['command'] == '!leveltest' or sar['command'] == '!lt') and self.game.players[sar['player_num']].get_admin_role() >= 20:
                if line.split(sar['command'])[1]:
                    user = line.split(sar['command'])[1].strip()
                    found, victim, msg = self.player_found(user)
                    if not found:
                        self.game.rcon_tell(sar['player_num'], msg)
                    else:
                        victim_admin_role = victim.get_admin_role()
                        if victim_admin_role > 0:
                            self.game.rcon_tell(sar['player_num'], "^7%s [^3@%s^7] is ^3%s ^7[^2%d^7] and registered since ^3%s" % (victim.get_name(), victim.get_player_id(), victim.roles[victim_admin_role], victim_admin_role, victim.get_first_seen_date()))
                        else:
                            self.game.rcon_tell(sar['player_num'], "^7%s [^3@%s^7] is ^3%s ^7[^2%d^7]" % (victim.get_name(), victim.get_player_id(), victim.roles[victim_admin_role], victim_admin_role))
                else:
                    self.game.rcon_tell(sar['player_num'], "^3Level %s [^2%d^3]: ^7%s" % (self.game.players[sar['player_num']].get_name(), self.game.players[sar['player_num']].get_admin_role(), self.game.players[sar['player_num']].roles[self.game.players[sar['player_num']].get_admin_role()]))

            # list - list all connected players
            elif sar['command'] == '!list' and self.game.players[sar['player_num']].get_admin_role() >= 20:
                msg = "^7Players online: %s" % ", ".join(["^3%s [^2%d^3]" % (player.get_name(), player.get_player_num()) for player in self.game.players.itervalues() if player.get_player_num() != BOT_PLAYER_NUM])
                self.game.rcon_tell(sar['player_num'], msg)

            # nextmap - display the next map in rotation
            elif (sar['command'] == '!nextmap' or sar['command'] == '@nextmap') and self.game.players[sar['player_num']].get_admin_role() >= 20:
                msg = self.get_nextmap()
                self.tell_say_message(sar, msg)

            # mute - mute or unmute a player
            elif sar['command'] == '!mute' and self.game.players[sar['player_num']].get_admin_role() >= 80:
                if line.split(sar['command'])[1]:
                    arg = line.split(sar['command'])[1].split()
                    if len(arg) > 1:
                        user = arg[0]
                        duration = arg[1]
                        if not duration.isdigit():
                            duration = ''
                    else:
                        user = arg[0]
                        duration = ''
                    found, victim, msg = self.player_found(user)
                    if not found:
                        self.game.rcon_tell(sar['player_num'], msg)
                    else:
                        self.game.send_rcon("mute %d %s" % (victim.get_player_num(), duration))
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !mute <name> [<seconds>]")

            # seen - display when the player was last seen
            elif sar['command'] == '!seen' and self.game.players[sar['player_num']].get_admin_role() >= 20:
                if line.split(sar['command'])[1]:
                    user = line.split(sar['command'])[1].strip()
                    found, victim, msg = self.player_found(user)
                    if not found:
                        self.game.rcon_tell(sar['player_num'], msg)
                    else:
                        if victim.get_registered_user():
                            self.game.rcon_tell(sar['player_num'], "^3%s ^7was last seen on %s" % (victim.get_name(), victim.get_last_visit()))
                        else:
                            self.game.rcon_tell(sar['player_num'], "^3%s ^7is not a registered user" % victim.get_name())
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !seen <name>")

            # shuffleteams
            elif (sar['command'] == '!shuffleteams' or sar['command'] == '!shuffle') and self.game.players[sar['player_num']].get_admin_role() >= 80:
                if not self.ffa_lms_gametype:
                    self.game.send_rcon('shuffleteams')
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Command is disabled for this game mode")

            # warninfo - display how many warnings the player has
            elif (sar['command'] == '!warninfo' or sar['command'] == '!wi') and self.game.players[sar['player_num']].get_admin_role() >= 20:
                if line.split(sar['command'])[1]:
                    user = line.split(sar['command'])[1].strip()
                    found, victim, msg = self.player_found(user)
                    if not found:
                        self.game.rcon_tell(sar['player_num'], msg)
                    else:
                        self.game.rcon_tell(sar['player_num'], "^3%s ^7has ^2%s ^7active warning(s)" % (victim.get_name(), victim.get_warning()))
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !warninfo <name>")

            # warn - warn user - !warn <name> [<reason>]
            elif (sar['command'] == '!warn' or sar['command'] == '!w') and self.game.players[sar['player_num']].get_admin_role() >= 80:
                if line.split(sar['command'])[1]:
                    arg = line.split(sar['command'])[1].split()
                    if len(arg) > 0:
                        user = arg[0]
                        reason = ' '.join(arg[1:])[:40].strip() if len(arg) > 1 else 'behave yourself'
                        found, victim, msg = self.player_found(user)
                        if not found:
                            self.game.rcon_tell(sar['player_num'], msg)
                        else:
                            warn_delay = 15
                            if victim.get_admin_role() >= self.game.players[sar['player_num']].get_admin_role():
                                self.game.rcon_tell(sar['player_num'], "^3You cannot warn an admin")
                            elif victim.get_last_warn_time() + warn_delay > time.time():
                                self.game.rcon_tell(sar['player_num'], "^3Only one warning per %d seconds can be issued" % warn_delay)
                            else:
                                show_alert = False
                                ban_duration = 0
                                if victim.get_warning() > 2:
                                    self.game.kick_player(victim.get_player_num(), reason='too many warnings')
                                    msg = "^2%s ^7was kicked, too many warnings" % victim.get_name()
                                else:
                                    if reason in reason_dict:
                                        warning = reason_dict[reason]
                                        if reason == 'tk' and victim.get_warning() > 1:
                                            ban_duration = victim.add_ban_point('tk, ban by %s' % self.game.players[sar['player_num']].get_name(), 600)
                                        elif reason == 'lang' and victim.get_warning() > 1:
                                            ban_duration = victim.add_ban_point('lang', 300)
                                        elif reason == 'spam' and victim.get_warning() > 1:
                                            ban_duration = victim.add_ban_point('spam', 300)
                                        elif reason == 'racism' and victim.get_warning() > 1:
                                            ban_duration = victim.add_ban_point('racism', 300)
                                    else:
                                        warning = reason
                                    victim.add_warning(warning)
                                    msg = "^1WARNING ^7[^3%d^7]: ^2%s^7: %s" % (victim.get_warning(), victim.get_name(), warning)
                                    # ban player if needed
                                    if ban_duration > 0:
                                        msg = "^2%s ^7banned for ^1%d minutes ^7for too many warnings" % (victim.get_name(), ban_duration)
                                        self.game.kick_player(victim.get_player_num(), reason='too many warnings')
                                    # show alert message for player with 3 warnings
                                    elif victim.get_warning() == 3:
                                        show_alert = True
                                self.game.rcon_say(msg)
                                if show_alert:
                                    self.game.rcon_say("^1ALERT: ^2%s ^7auto-kick from warnings if not cleared" % victim.get_name())
                    else:
                        self.game.rcon_tell(sar['player_num'], "^7Usage: !warn <name> [<reason>]")
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !warn <name> [<reason>]")

            # warnremove - remove a users last warning
            elif (sar['command'] == '!warnremove' or sar['command'] == '!wr') and self.game.players[sar['player_num']].get_admin_role() >= 80:
                if line.split(sar['command'])[1]:
                    user = line.split(sar['command'])[1].strip()
                    found, victim, msg = self.player_found(user)
                    if not found:
                        self.game.rcon_tell(sar['player_num'], msg)
                    else:
                        last_warning = victim.clear_last_warning()
                        if last_warning:
                            self.game.rcon_say("^7Last warning removed for %s: ^3%s" % (victim.get_name(), last_warning))
                        else:
                            self.game.rcon_tell(sar['player_num'], "^3%s ^7has no active warning" % victim.get_name())
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !warnremove <name>")

            # warns - list the warnings
            elif sar['command'] == '!warns' and self.game.players[sar['player_num']].get_admin_role() >= 20:
                keylist = reason_dict.keys()
                keylist.sort()
                self.game.rcon_tell(sar['player_num'], "^7Warnings: ^3%s" % ", ^3".join([key for key in keylist]))

            # warntest - test a warning
            elif (sar['command'] == '!warntest' or sar['command'] == '!wt') and self.game.players[sar['player_num']].get_admin_role() >= 20:
                if line.split(sar['command'])[1]:
                    reason = line.split(sar['command'])[1].strip()
                    warning = reason_dict[reason] if reason in reason_dict else reason
                else:
                    warning = 'behave yourself'
                self.game.rcon_tell(sar['player_num'], "^2TEST: ^1WARNING ^7[^31^7]: ^4%s" % warning)

## admin level 40
            # admins - list all the online admins
            elif (sar['command'] == '!admins' or sar['command'] == '@admins') and self.game.players[sar['player_num']].get_admin_role() >= 40:
                msg = self.get_admins_online()
                self.tell_say_message(sar, msg)

            # aliases - list the aliases of the player
            elif (sar['command'] == '!aliases' or sar['command'] == '@aliases' or sar['command'] == '!alias' or sar['command'] == '@alias') and self.game.players[sar['player_num']].get_admin_role() >= 40:
                if line.split(sar['command'])[1]:
                    user = line.split(sar['command'])[1].strip()
                    found, victim, msg = self.player_found(user)
                    if not found:
                        self.game.rcon_tell(sar['player_num'], msg)
                    else:
                        msg = "^7Aliases of ^5%s: ^3%s" % (victim.get_name(), victim.get_aliases())
                        self.tell_say_message(sar, msg)
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !alias <name>")

            # bigtext - display big message on screen
            elif sar['command'] == '!bigtext' and self.game.players[sar['player_num']].get_admin_role() >= 40:
                if line.split(sar['command'])[1]:
                    self.game.rcon_bigtext("%s" % line.split(sar['command'])[1].strip())
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !bigtext <text>")

            # say - say a message to all players
            elif sar['command'] == '!say' and self.game.players[sar['player_num']].get_admin_role() >= 60:
                if line.split(sar['command'])[1]:
                    self.game.rcon_say("^4%s: ^7%s" % (self.game.players[sar['player_num']].get_name(), line.split(sar['command'])[1].strip()))
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !say <text>")

            # !!<text> - allow spectator to say a message to players in-game
            elif sar['command'].startswith('!!') and self.game.players[sar['player_num']].get_admin_role() >= 40:
                if line.split('!!')[1]:
                    self.game.rcon_say("^4%s: ^7%s" % (self.game.players[sar['player_num']].get_name(), line.split('!!', 1)[1].strip()))

            # find - display the slot number of the player
            elif sar['command'] == '!find' and self.game.players[sar['player_num']].get_admin_role() >= 40:
                if line.split(sar['command'])[1]:
                    user = line.split(sar['command'])[1].strip()
                    found, victim, msg = self.player_found(user)
                    self.game.rcon_tell(sar['player_num'], msg)
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !find <name>")

            # force - force a player to the given team
            elif sar['command'] == '!force' and self.game.players[sar['player_num']].get_admin_role() >= 80:
                if line.split(sar['command'])[1]:
                    arg = line.split(sar['command'])[1].split()
                    if len(arg) > 1:
                        user = arg[0]
                        team = arg[1]
                        lock = False
                        if len(arg) > 2:
                            lock = True if arg[2] == 'lock' else False
                        team_dict = {'red': 'red', 'r': 'red', 're': 'red',
                                     'blue': 'blue', 'b': 'blue', 'bl': 'blue', 'blu': 'blue',
                                     'spec': 'spectator', 'spectator': 'spectator', 's': 'spectator', 'sp': 'spectator', 'spe': 'spectator',
                                     'green': 'green'}
                        found, victim, msg = self.player_found(user)
                        if not found:
                            self.game.rcon_tell(sar['player_num'], msg)
                        else:
                            if team in team_dict:
                                victim_player_num = victim.get_player_num()
                                self.game.rcon_forceteam(victim_player_num, team_dict[team])
                                self.game.rcon_tell(victim_player_num, "^3You are forced to: ^7%s" % team_dict[team])
                                # set team lock if defined
                                if lock:
                                    victim.set_team_lock(team_dict[team])
                                else:
                                    victim.set_team_lock(None)
                            else:
                                self.game.rcon_tell(sar['player_num'], "^7Usage: !force <name> <blue/red/spec> [<lock>]")
                    else:
                        self.game.rcon_tell(sar['player_num'], "^7Usage: !force <name> <blue/red/spec> [<lock>]")
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !force <name> <blue/red/spec> [<lock>]")

            # nuke - nuke a player
            elif sar['command'] == '!nuke' and self.game.players[sar['player_num']].get_admin_role() >= 100:
                if line.split(sar['command'])[1]:
                    user = line.split(sar['command'])[1].split()[0]
                    found, victim, msg = self.player_found(user)
                    if not found:
                        self.game.rcon_tell(sar['player_num'], msg)
                    else:
                        if victim.get_admin_role() >= self.game.players[sar['player_num']].get_admin_role():
                            self.game.rcon_tell(sar['player_num'], "^3Insufficient privileges to nuke an admin")
                        else:
                            self.game.send_rcon("nuke %d" % victim.get_player_num())
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !nuke <name>")

            # kick - kick a player
            elif (sar['command'] == '!kick' or sar['command'] == '!k') and self.game.players[sar['player_num']].get_admin_role() >= 80:
                if line.split(sar['command'])[1]:
                    arg = line.split(sar['command'])[1].split()
                    if self.game.players[sar['player_num']].get_admin_role() >= 80 and len(arg) == 1:
                        user = arg[0]
                        reason = '.'
                    elif len(arg) > 1:
                        user = arg[0]
                        reason = ' '.join(arg[1:])[:40].strip()
                    else:
                        user = reason = None
                    if user and reason:
                        found, victim, msg = self.player_found(user)
                        if not found:
                            self.game.rcon_tell(sar['player_num'], msg)
                        else:
                            if victim.get_admin_role() >= self.game.players[sar['player_num']].get_admin_role():
                                self.game.rcon_tell(sar['player_num'], "^3Insufficient privileges to kick an admin")
                            else:
                                msg = "^2%s ^7was kicked by %s" % (victim.get_name(), self.game.players[sar['player_num']].get_name())
                                if reason in reason_dict:
                                    kick_reason = reason_dict[reason]
                                    msg = "%s: ^3%s" % (msg, kick_reason)
                                elif reason == '.':
                                    kick_reason = ''
                                else:
                                    kick_reason = reason
                                    msg = "%s: ^3%s" % (msg, kick_reason)
                                self.game.kick_player(victim.get_player_num(), reason=kick_reason)
                                self.game.rcon_say(msg)
                    else:
                        self.game.rcon_tell(sar['player_num'], "^7You need to enter a reason: ^3!kick <name> <reason>")
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !kick <name> <reason>")

            # warnclear - clear the user warnings
            elif (sar['command'] == '!warnclear' or sar['command'] == '!wc') and self.game.players[sar['player_num']].get_admin_role() >= 80:
                if line.split(sar['command'])[1]:
                    user = line.split(sar['command'])[1].strip()
                    found, victim, msg = self.player_found(user)
                    if not found:
                        self.game.rcon_tell(sar['player_num'], msg)
                    else:
                        victim.clear_warning()
                        self.game.rcon_say("^1All warnings cleared for ^2%s" % victim.get_name())
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !warnclear <name>")

            # tempban - ban a player temporary for the given period (1 min to 24 hrs)
            elif (sar['command'] == '!tempban' or sar['command'] == '!tb') and self.game.players[sar['player_num']].get_admin_role() >= 80:
                if line.split(sar['command'])[1]:
                    arg = line.split(sar['command'])[1].split()
                    if len(arg) > 1:
                        user = arg[0]
                        duration, duration_output = self.convert_time(arg[1])
                        reason = ' '.join(arg[2:])[:40].strip() if len(arg) > 2 else 'tempban'
                        kick_reason = reason_dict[reason] if reason in reason_dict else '' if reason == 'tempban' else reason
                        found, victim, msg = self.player_found(user)
                        if not found:
                            self.game.rcon_tell(sar['player_num'], msg)
                        else:
                            if victim.get_admin_role() >= self.game.players[sar['player_num']].get_admin_role():
                                self.game.rcon_tell(sar['player_num'], "^3Insufficient privileges to ban an admin")
                            else:
                                if victim.ban(duration=duration, reason=reason, admin=self.game.players[sar['player_num']].get_name()):
                                    msg = "^2%s ^1banned ^7for ^3%s ^7by %s" % (victim.get_name(), duration_output, self.game.players[sar['player_num']].get_name())
                                    if kick_reason:
                                        msg = "%s: ^3%s" % (msg, kick_reason)
                                    self.game.rcon_say(msg)
                                else:
                                    self.game.rcon_tell(sar['player_num'], "^7This player has already a longer ban")
                                self.game.kick_player(player_num=victim.get_player_num(), reason=kick_reason)
                    else:
                        self.game.rcon_tell(sar['player_num'], "^7You need to enter a duration: ^3!tempban <name> <duration> [<reason>]")
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !tempban <name> <duration> [<reason>]")

## full admin level 60
            # scream - scream a message in different colors to all players
            elif sar['command'] == '!scream' and self.game.players[sar['player_num']].get_admin_role() >= 80:
                if line.split(sar['command'])[1]:
                    self.game.rcon_say("^1%s" % line.split(sar['command'])[1].strip())
                    self.game.rcon_say("^2%s" % line.split(sar['command'])[1].strip())
                    self.game.rcon_say("^3%s" % line.split(sar['command'])[1].strip())
                    self.game.rcon_say("^5%s" % line.split(sar['command'])[1].strip())
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !scream <text>")

            # slap - slap a player (a number of times); (1-15 times)
            elif sar['command'] == '!slap' and self.game.players[sar['player_num']].get_admin_role() >= 100:
                if line.split(sar['command'])[1]:
                    arg = line.split(sar['command'])[1].split()
                    if len(arg) > 1:
                        user = arg[0]
                        number = arg[1]
                        if not number.isdigit():
                            number = 1
                        else:
                            number = int(number)
                        if number > 15:
                            number = 15
                    else:
                        user = arg[0]
                        number = 1
                    found, victim, msg = self.player_found(user)
                    if not found:
                        self.game.rcon_tell(sar['player_num'], msg)
                    else:
                        if victim.get_admin_role() >= self.game.players[sar['player_num']].get_admin_role():
                            self.game.rcon_tell(sar['player_num'], "^3Insufficient privileges to slap an admin")
                        else:
                            for _ in xrange(0, number):
                                self.game.send_rcon("slap %d" % victim.get_player_num())
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !slap <name> [<amount>]")

            # swap - swap teams for player 1 and 2 (if in different teams)
            elif sar['command'] == '!swap' and self.game.players[sar['player_num']].get_admin_role() >= 80:
                if not self.ffa_lms_gametype:
                    if line.split(sar['command'])[1]:
                        arg = line.split(sar['command'])[1].split()
                        if len(arg) > 1:
                            player1 = arg[0]
                            player2 = arg[1]
                            found1, victim1, _ = self.player_found(player1)
                            found2, victim2, _ = self.player_found(player2)
                            if not found1 or not found2:
                                self.game.rcon_tell(sar['player_num'], '^3Player not found')
                            else:
                                team1 = victim1.get_team()
                                team2 = victim2.get_team()
                                if team1 == team2:
                                    self.game.rcon_tell(sar['player_num'], "^7Cannot swap, both players are in the same team")
                                else:
                                    game_data = self.game.get_gamestats()
                                    # remove team lock
                                    victim1.set_team_lock(None)
                                    victim2.set_team_lock(None)
                                    if game_data[Player.teams[team1]] < game_data[Player.teams[team2]]:
                                        self.game.rcon_forceteam(victim2.get_player_num(), Player.teams[team1])
                                        self.game.rcon_forceteam(victim1.get_player_num(), Player.teams[team2])
                                    else:
                                        self.game.rcon_forceteam(victim1.get_player_num(), Player.teams[team2])
                                        self.game.rcon_forceteam(victim2.get_player_num(), Player.teams[team1])
                                    self.game.rcon_say('^7Swapped player ^3%s ^7with ^3%s' % (victim1.get_name(), victim2.get_name()))
                        else:
                            self.game.rcon_tell(sar['player_num'], "^7Usage: !swap <name1> <name2>")
                    else:
                        self.game.rcon_tell(sar['player_num'], "^7Usage: !swap <name1> <name2>")
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Command is disabled for this game mode")

            # version - display the version of the bot
            elif sar['command'] == '!version' and self.game.players[sar['player_num']].get_admin_role() >= 60:
                self.game.rcon_tell(sar['player_num'], "^7Spunky Bot ^2v%s" % __version__)
                try:
                    get_latest = urllib2.urlopen('%s/version.txt' % self.base_url).read().strip()
                except urllib2.URLError:
                    get_latest = __version__
                if __version__ < get_latest:
                    self.game.rcon_tell(sar['player_num'], "^7A newer release ^6%s ^7is available, check ^3www.spunkybot.de" % get_latest)

            # veto - stop voting process
            elif sar['command'] == '!veto' and self.game.players[sar['player_num']].get_admin_role() >= 100:
                self.game.send_rcon('veto')

            # ci - kick player with connection interrupted
            elif sar['command'] == '!ci' and self.game.players[sar['player_num']].get_admin_role() >= 60:
                if line.split(sar['command'])[1]:
                    user = line.split(sar['command'])[1].strip()
                    player_ping = 0
                    found, victim, msg = self.player_found(user)
                    if not found:
                        self.game.rcon_tell(sar['player_num'], msg)
                    else:
                        # update rcon status
                        self.game.quake.rcon_update()
                        for player in self.game.quake.players:
                            if victim.get_player_num() == player.num:
                                player_ping = player.ping
                        if player_ping == 999:
                            self.game.kick_player(victim.get_player_num(), reason='connection interrupted, try to reconnect')
                            self.game.rcon_say("^2%s ^7was kicked by %s: ^4connection interrupted" % (victim.get_name(), self.game.players[sar['player_num']].get_name()))
                        else:
                            self.game.rcon_tell(sar['player_num'], "^3%s has no connection interrupted" % victim.get_name())
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !ci <name>")

            # ban - ban a player for 7 days
            elif (sar['command'] == '!ban' or sar['command'] == '!b') and self.game.players[sar['player_num']].get_admin_role() >= 80:
                if line.split(sar['command'])[1]:
                    arg = line.split(sar['command'])[1].split()
                    if len(arg) == 1 and self.game.players[sar['player_num']].get_admin_role() >= 80:
                        user = arg[0]
                        reason = "tempban"
                    elif len(arg) > 1:
                        user = arg[0]
                        reason = ' '.join(arg[1:])[:40].strip()
                    else:
                        user = reason = None
                    if user and reason:
                        found, victim, msg = self.player_found(user)
                        kick_reason = reason_dict[reason] if reason in reason_dict else '' if reason == 'tempban' else reason
                        if not found:
                            self.game.rcon_tell(sar['player_num'], msg)
                        else:
                            if victim.get_admin_role() >= self.game.players[sar['player_num']].get_admin_role():
                                self.game.rcon_tell(sar['player_num'], "^3Insufficient privileges to ban an admin")
                            else:
                                # ban for 7 days
                                if victim.ban(duration=604800, reason=reason, admin=self.game.players[sar['player_num']].get_name()):
                                    msg = "^2%s ^1banned ^7for ^37 days ^7by %s" % (victim.get_name(), self.game.players[sar['player_num']].get_name())
                                    if kick_reason:
                                        msg = "%s: ^3%s" % (msg, kick_reason)
                                    self.game.rcon_say(msg)
                                else:
                                    self.game.rcon_tell(sar['player_num'], "^7This player has already a longer ban")
                                self.game.kick_player(player_num=victim.get_player_num(), reason=kick_reason)
                    else:
                        self.game.rcon_tell(sar['player_num'], "^7You need to enter a reason: ^3!ban <name> <reason>")
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !ban <name> <reason>")

            # baninfo - display active bans of a player
            elif (sar['command'] == '!baninfo' or sar['command'] == '!bi') and self.game.players[sar['player_num']].get_admin_role() >= 60:
                if line.split(sar['command'])[1]:
                    user = line.split(sar['command'])[1].strip()
                    found, victim, msg = self.player_found(user)
                    if not found:
                        self.game.rcon_tell(sar['player_num'], msg)
                    else:
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
                        guid = victim.get_guid()
                        values = (timestamp, guid)
                        curs.execute("SELECT `expires` FROM `ban_list` WHERE `expires` > ? AND `guid` = ?", values)
                        result = curs.fetchone()
                        if result:
                            self.game.rcon_tell(sar['player_num'], "^3%s ^7has an active ban until [^1%s^7]" % (victim.get_name(), str(result[0])))
                        else:
                            self.game.rcon_tell(sar['player_num'], "^3%s ^7has no active ban" % victim.get_name())
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !baninfo <name>")

            # rain - enables or disables rain - !rain <on/off>
            elif sar['command'] == '!rain' and self.game.players[sar['player_num']].get_admin_role() >= 60:
                if line.split(sar['command'])[1]:
                    arg = line.split(sar['command'])[1].strip()
                    if arg == "off":
                        self.game.send_rcon('g_enableprecip 0')
                        self.game.rcon_tell(sar['player_num'], "^7Rain: ^1Off")
                    elif arg == "on":
                        self.game.send_rcon('g_enableprecip 1')
                        self.game.rcon_tell(sar['player_num'], "^7Rain: ^2On")
                    else:
                        self.game.rcon_tell(sar['player_num'], "^7Usage: !rain <on/off>")
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !rain <on/off>")

## senior admin level 80
            # kiss - clear all player warnings - !clear [<player>]
            elif (sar['command'] == '!kiss' or sar['command'] == '!clear') and self.game.players[sar['player_num']].get_admin_role() >= 80:
                if line.split(sar['command'])[1]:
                    user = line.split(sar['command'])[1].strip()
                    found, victim, msg = self.player_found(user)
                    if not found:
                        self.game.rcon_tell(sar['player_num'], msg)
                    else:
                        victim.clear_warning()
                        self.game.rcon_say("^1All warnings cleared for ^2%s" % victim.get_name())
                else:
                    for player in self.game.players.itervalues():
                        player.clear_warning()
                    self.game.rcon_say("^1All player warnings cleared")

            # map - load given map
            elif sar['command'] == '!map' and self.game.players[sar['player_num']].get_admin_role() >= 80:
                if line.split(sar['command'])[1]:
                    arg = line.split(sar['command'])[1].strip()
                    found, newmap, msg = self.map_found(arg)
                    if not found:
                        self.game.rcon_tell(sar['player_num'], msg)
                    else:
                        self.game.send_rcon('g_nextmap %s' % newmap)
                        self.game.next_mapname = newmap
                        self.game.rcon_tell(sar['player_num'], "^7Changing Map to: ^3%s" % newmap)
                        self.game.send_rcon('cyclemap')
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !map <ut4_name>")

            # maps - display all available maps
            elif (sar['command'] == '!maps' or sar['command'] == '@maps') and self.game.players[sar['player_num']].get_admin_role() >= 80:
                msg = "^7Available Maps: ^3%s" % ', ^3'.join(self.game.get_all_maps())
                self.tell_say_message(sar, msg)

            # maprestart - restart the map
            elif sar['command'] == '!maprestart' and self.game.players[sar['player_num']].get_admin_role() >= 80:
                self.game.send_rcon('restart')
                self.stats_reset()

            # moon - activate Moon mode (low gravity)
            elif sar['command'] == '!moon' and self.game.players[sar['player_num']].get_admin_role() >= 100:
                if line.split(sar['command'])[1]:
                    arg = line.split(sar['command'])[1].strip()
                    if arg == "off":
                        self.game.send_rcon('g_gravity 800')
                        self.game.rcon_tell(sar['player_num'], "^7Moon mode: ^1Off")
                    elif arg == "on":
                        self.game.send_rcon('g_gravity 100')
                        self.game.rcon_tell(sar['player_num'], "^7Moon mode: ^2On")
                    else:
                        self.game.rcon_tell(sar['player_num'], "^7Usage: !moon <on/off>")
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !moon <on/off>")

            # cyclemap - start next map in rotation
            elif sar['command'] == '!cyclemap' and self.game.players[sar['player_num']].get_admin_role() >= 80:
                self.game.send_rcon('cyclemap')

            # setnextmap - set the given map as nextmap
            elif sar['command'] == '!setnextmap' and self.game.players[sar['player_num']].get_admin_role() >= 80:
                if line.split(sar['command'])[1]:
                    arg = line.split(sar['command'])[1].strip()
                    found, nextmap, msg = self.map_found(arg)
                    if not found:
                        self.game.rcon_tell(sar['player_num'], msg)
                    else:
                        self.game.send_rcon('g_nextmap %s' % nextmap)
                        self.game.next_mapname = nextmap
                        self.game.rcon_tell(sar['player_num'], "^7Next Map set to: ^3%s" % nextmap)
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !setnextmap <ut4_name>")

            # swapteams - swap current teams
            elif sar['command'] == '!swapteams' and self.game.players[sar['player_num']].get_admin_role() >= 80:
                self.game.send_rcon('swapteams')

            # exec - execute given config file
            elif sar['command'] == '!exec' and self.game.players[sar['player_num']].get_admin_role() >= 100:
                if line.split(sar['command'])[1]:
                    arg = line.split(sar['command'])[1].strip()
                    self.game.send_rcon('exec %s' % arg)
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !exec <filename>")

            # kill - kill a player
            elif sar['command'] == '!kill' and self.game.players[sar['player_num']].get_admin_role() >= 100:
                if self.urt_modversion > 41:
                    if line.split(sar['command'])[1]:
                        user = line.split(sar['command'])[1].strip()
                        found, victim, msg = self.player_found(user)
                        if not found:
                            self.game.rcon_tell(sar['player_num'], msg)
                        else:
                            if victim.get_admin_role() >= self.game.players[sar['player_num']].get_admin_role():
                                self.game.rcon_tell(sar['player_num'], "^3Insufficient privileges to kill an admin")
                            else:
                                self.game.send_rcon("smite %d" % victim.get_player_num())
                    else:
                        self.game.rcon_tell(sar['player_num'], "^7Usage: !kill <name>")
                else:
                    self.game.rcon_tell(sar['player_num'], "^7The command ^3!kill ^7is not supported")

            # lookup - search for player in database
            elif (sar['command'] == '!lookup' or sar['command'] == '!l') and self.game.players[sar['player_num']].get_admin_role() >= 80:
                if line.split(sar['command'])[1]:
                    arg = line.split(sar['command'])[1].strip()
                    search = '%' + arg + '%'
                    lookup = (search,)
                    result = curs.execute("SELECT * FROM `player` WHERE `name` like ? ORDER BY `time_joined` DESC LIMIT 8", lookup).fetchall()
                    for row in result:
                        self.game.rcon_tell(sar['player_num'], "^7[^2@%s^7] %s ^7[^1%s^7]" % (str(row[0]), str(row[2]), str(row[4])), False)  # 0=ID, 1=GUID, 2=Name, 3=IP, 4=Date
                    if not result:
                        self.game.rcon_tell(sar['player_num'], "^3No Player found matching %s" % arg)
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !lookup <name>")

            # permban - ban a player permanent
            elif (sar['command'] == '!permban' or sar['command'] == '!pb') and self.game.players[sar['player_num']].get_admin_role() >= 100:
                if line.split(sar['command'])[1]:
                    arg = line.split(sar['command'])[1].split()
                    if len(arg) > 1:
                        user = arg[0]
                        reason = ' '.join(arg[1:])[:40].strip()
                        found, victim, msg = self.player_found(user)
                        if not found:
                            self.game.rcon_tell(sar['player_num'], msg)
                        else:
                            if victim.get_admin_role() >= self.game.players[sar['player_num']].get_admin_role():
                                self.game.rcon_tell(sar['player_num'], "^3Insufficient privileges to ban an admin")
                            else:
                                # ban for 20 years
                                victim.ban(duration=630720000, reason=reason, admin=self.game.players[sar['player_num']].get_name())
                                self.game.rcon_say("^2%s ^1banned permanently ^7by %s: ^4%s" % (victim.get_name(), self.game.players[sar['player_num']].get_name(), reason))
                                self.game.kick_player(victim.get_player_num())
                                # add IP address to bot-banlist.txt
                                with open(os.path.join(HOME, 'bot-banlist.txt'), 'a') as banlist:
                                    banlist.write("%s:-1   // %s    banned on  %s, reason : %s\n" % (victim.get_ip_address(), victim.get_name(), time.strftime("%d/%m/%Y (%H:%M)", time.localtime(time.time())), reason))
                    else:
                        self.game.rcon_tell(sar['player_num'], "^7You need to enter a reason: ^3!permban <name> <reason>")
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !permban <name> <reason>")

            # makereg - make a player a regular (Level 2) user
            elif (sar['command'] == '!makereg' or sar['command'] == '!mr') and self.game.players[sar['player_num']].get_admin_role() >= 80:
                if line.split(sar['command'])[1]:
                    user = line.split(sar['command'])[1].strip()
                    found, victim, msg = self.player_found(user)
                    if not found:
                        self.game.rcon_tell(sar['player_num'], msg)
                    else:
                        if victim.get_registered_user():
                            if victim.get_admin_role() < 2:
                                victim.update_db_admin_role(role=2)
                                self.game.rcon_tell(sar['player_num'], "^3%s put in group ^7Regular" % victim.get_name())
                            else:
                                self.game.rcon_tell(sar['player_num'], "^3%s is already in a higher level group" % victim.get_name())
                        else:
                            # register new user in DB and set role to 2
                            victim.register_user_db(role=2)
                            self.game.rcon_tell(sar['player_num'], "^3%s put in group ^7Regular" % victim.get_name())
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !makereg <name>")

            # putgroup - add a client to a group
            elif sar['command'] == '!putgroup' and self.game.players[sar['player_num']].get_admin_role() >= 100:
                if line.split(sar['command'])[1]:
                    arg = line.split(sar['command'])[1].split()
                    if len(arg) > 1:
                        user = arg[0]
                        right = arg[1]
                        found, victim, msg = self.player_found(user)
                        if not found:
                            self.game.rcon_tell(sar['player_num'], msg)
                        else:
                            if victim.get_registered_user():
                                new_role = victim.get_admin_role()
                            else:
                                # register new user in DB and set role to 1
                                victim.register_user_db(role=1)
                                new_role = 1

                            if right == "user" and victim.get_admin_role() < 80:
                                self.game.rcon_tell(sar['player_num'], "^3%s put in group ^7User" % victim.get_name())
                                new_role = 1
                            elif (right == "reg" or right == "regular") and victim.get_admin_role() < 80:
                                self.game.rcon_tell(sar['player_num'], "^3%s put in group ^7Regular" % victim.get_name())
                                new_role = 2
                            elif (right == "mod" or right == "moderator") and victim.get_admin_role() < 80:
                                self.game.rcon_tell(sar['player_num'], "^3%s added as ^7Moderator" % victim.get_name())
                                self.game.rcon_tell(victim.get_player_num(), "^3You are added as ^7Moderator")
                                new_role = 20
                            elif right == "admin" and victim.get_admin_role() < 80:
                                self.game.rcon_tell(sar['player_num'], "^3%s added as ^7Admin" % victim.get_name())
                                self.game.rcon_tell(victim.get_player_num(), "^3You are added as ^7Admin")
                                new_role = 40
                            elif right == "fulladmin" and victim.get_admin_role() < 80:
                                self.game.rcon_tell(sar['player_num'], "^3%s added as ^7Full Admin" % victim.get_name())
                                self.game.rcon_tell(victim.get_player_num(), "^3You are added as ^7Full Admin")
                                new_role = 60
                            # Note: senioradmin level can only be set by head admin
                            elif right == "senioradmin" and self.game.players[sar['player_num']].get_admin_role() == 100 and victim.get_player_num() != sar['player_num']:
                                self.game.rcon_tell(sar['player_num'], "^3%s added as ^6Senior Admin" % victim.get_name())
                                self.game.rcon_tell(victim.get_player_num(), "^3You are added as ^6Senior Admin")
                                new_role = 80
                            else:
                                self.game.rcon_tell(sar['player_num'], "^3Sorry, you cannot put %s in group <%s>" % (victim.get_name(), right))
                            victim.update_db_admin_role(role=new_role)
                    else:
                        self.game.rcon_tell(sar['player_num'], "^7Usage: !putgroup <name> <group>")
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !putgroup <name> <group>")

            # banlist - display the last active 10 bans
            elif sar['command'] == '!banlist' and self.game.players[sar['player_num']].get_admin_role() >= 80:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
                values = (timestamp,)
                result = curs.execute("SELECT * FROM `ban_list` WHERE `expires` > ? ORDER BY `timestamp` DESC LIMIT 10", values).fetchall()
                banlist = ['^7[^2@%s^7] %s' % (result[item][0], result[item][2]) for item in xrange(len(result))]  # 0=ID,2=Name
                msg = 'Currently no one is banned' if not banlist else str(", ".join(banlist))
                self.game.rcon_tell(sar['player_num'], "^7Banlist: %s" % msg)

            # lastbans - list the last 4 bans
            elif (sar['command'] == '!lastbans' or sar['command'] == '!bans') and self.game.players[sar['player_num']].get_admin_role() >= 80:
                result = curs.execute("SELECT * FROM `ban_list` ORDER BY `timestamp` DESC LIMIT 4").fetchall()
                lastbanlist = ['^3[^2@%s^3] ^7%s ^3(^1%s^3)' % (result[item][0], result[item][2], result[item][4]) for item in xrange(len(result))]
                for item in lastbanlist:
                    self.game.rcon_tell(sar['player_num'], str(item))

            # unban - unban a player from the database via ID
            elif sar['command'] == '!unban' and self.game.players[sar['player_num']].get_admin_role() >= 100:
                if line.split(sar['command'])[1]:
                    arg = line.split(sar['command'])[1].strip().lstrip('@')
                    if arg.isdigit():
                        values = (int(arg),)
                        curs.execute("SELECT `guid`,`name`,`ip_address` FROM `ban_list` WHERE `id` = ?", values)
                        result = curs.fetchone()
                        if result:
                            guid = result[0]
                            name = str(result[1])
                            ip_addr = str(result[2])
                            curs.execute("DELETE FROM `ban_list` WHERE `id` = ?", values)
                            conn.commit()
                            self.game.rcon_tell(sar['player_num'], "^7Player ^2%s ^7unbanned" % name)
                            values = (guid, ip_addr)
                            curs.execute("DELETE FROM `ban_list` WHERE `guid` = ? OR ip_address = ?", values)
                            conn.commit()
                            self.game.rcon_tell(sar['player_num'], "^7Try to remove duplicates of [^1%s^7]" % ip_addr)
                        else:
                            self.game.rcon_tell(sar['player_num'], "^7Invalid ID, no Player found")
                    else:
                        self.game.rcon_tell(sar['player_num'], "^7Usage: !unban <@ID>")
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !unban <@ID>")

## head admin level 100
            # password - set private server password
            elif sar['command'] == '!password' and self.game.players[sar['player_num']].get_admin_role() == 100:
                if line.split(sar['command'])[1]:
                    arg = line.split(sar['command'])[1].strip()
                    self.game.send_rcon('g_password %s' % arg)
                    self.game.rcon_tell(sar['player_num'], "^7Password set to '%s' - Server is private" % arg)
                else:
                    self.game.send_rcon('g_password ""')
                    self.game.rcon_tell(sar['player_num'], "^7Password removed - Server is public")

            # reload
            elif sar['command'] == '!reload' and self.game.players[sar['player_num']].get_admin_role() == 100:
                self.game.send_rcon('reload')

            # ungroup - remove the admin level from a player
            elif sar['command'] == '!ungroup' and self.game.players[sar['player_num']].get_admin_role() == 100:
                if line.split(sar['command'])[1]:
                    user = line.split(sar['command'])[1].strip()
                    found, victim, msg = self.player_found(user)
                    if not found:
                        self.game.rcon_tell(sar['player_num'], msg)
                    else:
                        if 1 < victim.get_admin_role() < 100:
                            self.game.rcon_tell(sar['player_num'], "^3%s put in group User" % victim.get_name())
                            victim.update_db_admin_role(role=1)
                        else:
                            self.game.rcon_tell(sar['player_num'], "^3Sorry, you cannot put %s in group User" % victim.get_name())
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Usage: !ungroup <name>")

## iamgod
            # iamgod - register user as Head Admin
            elif sar['command'] == '!iamgod':
                if self.iamgod:
                    if not self.game.players[sar['player_num']].get_registered_user():
                        # register new user in DB and set admin role to 100
                        self.game.players[sar['player_num']].register_user_db(role=100)
                    else:
                        self.game.players[sar['player_num']].update_db_admin_role(role=100)
                    self.iamgod = False
                    self.game.rcon_tell(sar['player_num'], "^7You are registered as ^6Head Admin")

## unknown command
            elif sar['command'].startswith('!') and len(sar['command']) > 1 and self.game.players[sar['player_num']].get_admin_role() > 20:
                if sar['command'].lstrip('!') in self.senioradmin_cmds:
                    self.game.rcon_tell(sar['player_num'], "^7Insufficient privileges to use command ^3%s" % sar['command'])
                else:
                    self.game.rcon_tell(sar['player_num'], "^7Unknown command ^3%s" % sar['command'])

    def get_admins_online(self):
        """
        return list of Admins online
        """
        liste = "%s" % ", ".join(["^3%s [^2%d^3]" % (player.get_name(), player.get_admin_role()) for player in self.game.players.itervalues() if player.get_admin_role() >= 20])
        if liste:
            msg = "^7Admins online: %s" % liste
        else:
            msg = "^7No admins online"
        return msg

    def get_nextmap(self):
        """
        return the next map in the mapcycle
        """
        g_nextmap = self.game.get_cvar('g_nextmap')
        if g_nextmap and g_nextmap.split(" ")[0].strip() in self.game.get_all_maps():
            msg = "^7Next Map: ^3%s" % g_nextmap
            self.game.next_mapname = g_nextmap
        else:
            msg = "^7Next Map: ^3%s" % self.game.next_mapname
        return msg

    def tell_say_message(self, sar, msg):
        """
        display message in private or global chat
        """
        if sar['command'].startswith('@'):
            self.game.rcon_say(msg)
        else:
            self.game.rcon_tell(sar['player_num'], msg)

    def convert_time(self, time_string):
        """
        convert time string in duration and time unit
        """
        if time_string.endswith('h'):
            duration_string = time_string.rstrip('h')
            duration = int(duration_string) * 3600 if duration_string.isdigit() else 3600
            duration_output = "1 hour" if duration == 3600 else "%s hours" % duration_string
        elif time_string.endswith('m'):
            duration_string = time_string.rstrip('m')
            duration = int(duration_string) * 60 if duration_string.isdigit() else 60
            duration_output = "1 minute" if duration == 60 else "%s minutes" % duration_string
            if duration > 3600:
                calc = int(round(duration / 3600))
                duration_output = "1 hour" if calc == 1 else "%s hours" % calc
        else:
            duration = 3600
            duration_output = "1 hour"
        # minimum ban duration = 1 hour
        if duration == 0:
            duration = 3600
            duration_output = "1 hour"
        # limit to max duration = 24 hours
        elif duration > 86400:
            duration = 86400
            duration_output = "24 hours"
        return duration, duration_output

    def handle_flag(self, line):
        """
        handle flag
        """
        tmp = line.split()
        player_num = int(tmp[0])
        action = tmp[1]
        with self.players_lock:
            player = self.game.players[player_num]
            if action == '1:':
                player.return_flag()
                logger.debug("Player %d returned the flag", player_num)
            elif action == '2:':
                player.capture_flag()
                cap_count = player.get_flags_captured()
                self.game.send_rcon("^7%s has captured ^2%s ^7flag%s" % (player.get_name(), cap_count, 's' if cap_count > 1 else ''))
                logger.debug("Player %d captured the flag", player_num)

    def handle_bomb(self, line):
        """
        handle bomb
        """
        tmp = line.split("is") if "Bombholder" in line else line.split("by")
        action = tmp[0].strip()
        player_num = int(tmp[1].rstrip('!').strip())
        with self.players_lock:
            player = self.game.players[player_num]
            if action == 'Bomb was defused':
                player.defused_bomb()
                logger.debug("Player %d defused the bomb", player_num)
                self.handle_teams_ts_mode('Blue')
            elif action == 'Bomb was planted':
                player.planted_bomb()
                logger.debug("Player %d planted the bomb", player_num)
                if self.spam_bomb_planted_msg:
                    self.game.rcon_say("^1Bomb has been planted!")
                    self.game.rcon_say("^1Bomb has been planted!")
            elif action == 'Bomb was tossed':
                player.bomb_tossed()
            elif action == 'Bomb has been collected':
                player.is_bombholder()
            elif action == 'Bombholder':
                player.is_bombholder()

    def handle_bomb_exploded(self):
        """
        handle bomb exploded
        """
        logger.debug("Bomb exploded!")
        self.handle_teams_ts_mode('Red')

    def handle_teams_ts_mode(self, line):
        """
        handle team balance in Team Survivor mode
        """
        logger.debug("SurvivorWinner: %s team", line)
        self.autobalancer()
        if self.ts_do_team_balance:
            self.allow_cmd_teams = True
            self.handle_team_balance()
            if self.allow_cmd_teams_round_end:
                self.allow_cmd_teams = False

    def handle_team_balance(self):
        """
        balance teams if needed
        """
        with self.players_lock:
            game_data = self.game.get_gamestats()
            if (abs(game_data[Player.teams[1]] - game_data[Player.teams[2]])) > 1:
                if self.allow_cmd_teams:
                    self.game.balance_teams(game_data)
                    self.ts_do_team_balance = False
                    logger.debug("Balance teams by user request")
                else:
                    if self.ts_gametype or self.bomb_gametype or self.freeze_gametype:
                        self.ts_do_team_balance = True
                        self.game.rcon_say("^7Teams will be balanced at the end of this round!")
            else:
                self.game.rcon_say("^7Teams are already balanced")
                self.ts_do_team_balance = False

    def autobalancer(self):
        """
        auto balance teams at the end of the round if needed
        """
        if self.teams_autobalancer:
            with self.players_lock:
                game_data = self.game.get_gamestats()
                if (abs(game_data[Player.teams[1]] - game_data[Player.teams[2]])) > 1:
                    self.game.balance_teams(game_data)
                    logger.debug("Autobalancer performed team balance")
                self.ts_do_team_balance = False

    def handle_freeze(self, line):
        """
        handle freeze
        """
        info = line.split(":", 1)[0].split()
        player_num = int(info[0])
        with self.players_lock:
            self.game.players[player_num].freeze()

    def handle_thawout(self, line):
        """
        handle thaw out
        """
        info = line.split(":", 1)[0].split()
        player_num = int(info[0])
        with self.players_lock:
            self.game.players[player_num].thawout()

    def handle_awards(self):
        """
        display awards and personal stats at the end of the round
        """
        most_kills = 0
        most_flags = 0
        most_streak = 0
        most_hs = 0
        most_frozen = 0
        most_thawouts = 0
        most_defused = 0
        most_planted = 0
        most_he_kills = 0
        most_knife_kills = 0
        fastest_cap = 999
        most_flag_returns = 0
        flagrunner = ""
        serialkiller = ""
        streaker = ""
        freezer = ""
        thawouter = ""
        headshooter = ""
        defused_by = ""
        planted_by = ""
        nader = ""
        knifer = ""
        fastrunner = ""
        defender = ""
        msg = []
        append = msg.append
        with self.players_lock:
            for player in self.game.players.itervalues():
                player_num = player.get_player_num()
                if player_num == BOT_PLAYER_NUM:
                    continue
                player_name = player.get_name()
                player_kills = player.get_kills()
                player_headshots = player.get_headshots()
                if player.get_flags_captured() > most_flags:
                    most_flags = player.get_flags_captured()
                    flagrunner = player_name
                if player_kills > most_kills:
                    most_kills = player_kills
                    serialkiller = player_name
                if player.get_max_kill_streak() > most_streak:
                    most_streak = player.get_max_kill_streak()
                    streaker = player_name
                if player_headshots > most_hs:
                    most_hs = player_headshots
                    headshooter = player_name
                if player.get_freeze() > most_frozen:
                    most_frozen = player.get_freeze()
                    freezer = player_name
                if player.get_thawout() > most_thawouts:
                    most_thawouts = player.get_thawout()
                    thawouter = player_name
                if player.get_defused_bomb() > most_defused:
                    most_defused = player.get_defused_bomb()
                    defused_by = player_name
                if player.get_planted_bomb() > most_planted:
                    most_planted = player.get_planted_bomb()
                    planted_by = player_name
                if player.get_he_kills() > most_he_kills:
                    most_he_kills = player.get_he_kills()
                    nader = player_name
                if player.get_knife_kills() > most_knife_kills:
                    most_knife_kills = player.get_knife_kills()
                    knifer = player_name
                if 0 < player.get_flag_capture_time() < fastest_cap:
                    fastest_cap = player.get_flag_capture_time()
                    fastrunner = player_name
                if player.get_flags_returned() > most_flag_returns:
                    most_flag_returns = player.get_flags_returned()
                    defender = player_name

                # display personal stats at the end of the round, stats for players in spec will not be displayed
                if player.get_team() != 3:
                    if self.freeze_gametype:
                        self.game.rcon_tell(player_num, "^7Stats %s: ^7F ^2%d ^7T ^3%d ^7HS ^1%d ^7TK ^1%d" % (player_name, player.get_freeze(), player.get_thawout(), player.get_headshots(), player.get_team_kill_count()))
                    else:
                        self.game.rcon_tell(player_num, "^7Stats %s: ^7K ^2%d ^7D ^3%d ^7HS ^1%d ^7TK ^1%d" % (player_name, player_kills, player.get_deaths(), player_headshots, player.get_team_kill_count()))

            # get Awards
            if most_flags > 1:
                append("^7%s: ^2%d ^4caps" % (flagrunner, most_flags))
            if most_planted > 1:
                append("^7%s: ^2%d ^5planted" % (planted_by, most_planted))
            if most_defused > 1:
                append("^7%s: ^2%d ^4defused" % (defused_by, most_defused))
            if most_frozen > 1:
                append("^7%s: ^2%d ^3freezes" % (freezer, most_frozen))
            if most_thawouts > 1:
                append("^7%s: ^2%d ^4thaws" % (thawouter, most_thawouts))
            if most_kills > 1:
                append("^7%s: ^2%d ^3kills" % (serialkiller, most_kills))
            if most_streak > 1:
                append("^7%s: ^2%d ^6streaks" % (streaker, most_streak))
            if most_hs > 1:
                append("^7%s: ^2%d ^1heads" % (headshooter, most_hs))

            # HE grenade kills
            if most_he_kills > 1:
                self.game.rcon_say("^2Most HE grenade kills: ^7%s (^1%d ^7HE kills)" % (nader, most_he_kills))

            if most_knife_kills > 1:
                self.game.rcon_say("^2Most knife kills: ^7%s (^1%d ^7kills)" % (knifer, most_knife_kills))

            # CTF statistics
            if fastest_cap < 999:
                self.game.rcon_say("^2Fastest cap: ^7%s (^1%s ^7sec)" % (fastrunner, fastest_cap))
            if most_flag_returns > 1:
                self.game.rcon_say("^2Best defender: ^7%s (^1%d ^7flag returns)" % (defender, most_flag_returns))

            # display Awards
            if msg:
                self.game.rcon_say("^1AWARDS: %s" % " ^7- ".join(msg))


### CLASS Player ###
class Player(object):
    """
    Player class
    """
    teams = {0: "green", 1: "red", 2: "blue", 3: "spectator"}
    roles = {0: "Guest", 1: "User", 2: "Regular", 20: "Moderator", 40: "Admin", 60: "Full Admin", 80: "Senior Admin", 100: "Head Admin"}

    def __init__(self, player_num, ip_address, guid, name, auth=''):
        """
        create a new instance of Player
        """
        self.player_num = player_num
        self.guid = guid
        self.name = name.replace(' ', '')
        self.authname = auth
        self.player_id = 0
        self.aliases = []
        self.registered_user = False
        self.num_played = 0
        self.last_visit = 0
        self.admin_role = 0
        self.first_seen = None
        self.kills = 0
        self.froze = 0
        self.thawouts = 0
        self.db_kills = 0
        self.killing_streak = 0
        self.max_kill_streak = 0
        self.db_killing_streak = 0
        self.deaths = 0
        self.db_deaths = 0
        self.db_suicide = 0
        self.head_shots = 0
        self.db_head_shots = 0
        self.hitzone = {'body': 0, 'arms': 0, 'legs': 0}
        self.all_hits = 0
        self.he_kills = 0
        self.knife_kills = 0
        self.tk_count = 0
        self.db_tk_count = 0
        self.db_team_death = 0
        self.tk_victim_names = []
        self.tk_killer_names = []
        self.ping_value = 0
        self.warn_list = []
        self.last_warn_time = 0
        self.flags_captured = 0
        self.flags_returned = 0
        self.flag_capture_time = 999
        self.bombholder = False
        self.bomb_carrier_killed = 0
        self.killed_with_bomb = 0
        self.bomb_planted = 0
        self.bomb_defused = 0
        self.address = ip_address
        self.team = 3
        self.team_lock = None
        self.time_joined = time.time()
        self.welcome_msg = True
        self.country = None
        self.ban_id = 0

        self.prettyname = self.name
        # remove color characters from name
        for item in xrange(10):
            self.prettyname = self.prettyname.replace('^%d' % item, '')

        # GeoIP lookup
        info = GEOIP.lookup(ip_address)
        if info.country:
            self.country = "%s (%s)" % (info.country_name, info.country)

        # check ban_list
        now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.time_joined))
        values = (self.guid, now)
        curs.execute("SELECT `id` FROM `ban_list` WHERE `guid` = ? AND `expires` > ?", values)
        result = curs.fetchone()
        if result:
            self.ban_id = result[0]
        else:
            values = (self.address, now)
            curs.execute("SELECT `id` FROM `ban_list` WHERE `ip_address` = ? AND `expires` > ?", values)
            result = curs.fetchone()
            if result:
                self.ban_id = result[0]

    def ban(self, duration=900, reason='tk', admin=None):
        if admin:
            reason = "%s, ban by %s" % (reason, admin)
        unix_expiration = duration + time.time()
        expire_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(unix_expiration))
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
        values = (self.guid,)
        curs.execute("SELECT `expires` FROM `ban_list` WHERE `guid` = ?", values)
        result = curs.fetchone()
        if result:
            if result[0] < expire_date:
                values = (self.address, expire_date, self.guid)
                curs.execute("UPDATE `ban_list` SET `ip_address` = ?,`expires` = ? WHERE `guid` = ?", values)
                conn.commit()
                return True
            else:
                values = (self.address, self.guid)
                curs.execute("UPDATE `ban_list` SET `ip_address` = ? WHERE `guid` = ?", values)
                conn.commit()
                return False
        else:
            values = (self.player_id, self.guid, self.prettyname, self.address, expire_date, timestamp, reason)
            curs.execute("INSERT INTO `ban_list` (`id`,`guid`,`name`,`ip_address`,`expires`,`timestamp`,`reason`) VALUES (?,?,?,?,?,?,?)", values)
            conn.commit()
            return True

    def add_ban_point(self, point_type, duration):
        unix_expiration = duration + time.time()
        expire_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(unix_expiration))
        values = (self.guid, point_type, expire_date)
        # add ban_point to database
        curs.execute("INSERT INTO `ban_points` (`guid`,`point_type`,`expires`) VALUES (?,?,?)", values)
        conn.commit()
        # check amount of ban_points
        values = (self.guid, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())))
        curs.execute("SELECT COUNT(*) FROM `ban_points` WHERE `guid` = ? AND `expires` > ?", values)
        # ban player when he gets more than 1 ban_point
        if curs.fetchone()[0] > 1:
            # ban duration multiplied by 3
            ban_duration = duration * 3
            self.ban(duration=ban_duration, reason=point_type)
            return ban_duration / 60
        else:
            return 0

    def reset(self):
        self.kills = 0
        self.froze = 0
        self.thawouts = 0
        self.killing_streak = 0
        self.max_kill_streak = 0
        self.deaths = 0
        self.head_shots = 0
        self.hitzone = {'body': 0, 'arms': 0, 'legs': 0}
        self.all_hits = 0
        self.he_kills = 0
        self.knife_kills = 0
        self.tk_count = 0
        self.tk_victim_names = []
        self.tk_killer_names = []
        self.warn_list = []
        self.last_warn_time = 0
        self.flags_captured = 0
        self.flags_returned = 0
        self.flag_capture_time = 999
        self.bombholder = False
        self.bomb_carrier_killed = 0
        self.killed_with_bomb = 0
        self.bomb_planted = 0
        self.bomb_defused = 0
        self.team_lock = None

    def reset_flag_stats(self):
        self.flags_captured = 0
        self.flags_returned = 0
        self.flag_capture_time = 999

    def save_info(self):
        if self.registered_user:
            ratio = round(float(self.db_kills) / float(self.db_deaths), 2) if self.db_deaths > 0 else 1.0
            values = (self.db_kills, self.db_deaths, self.db_head_shots, self.db_tk_count, self.db_team_death, self.db_killing_streak, self.db_suicide, ratio, self.guid)
            curs.execute("UPDATE `xlrstats` SET `kills` = ?,`deaths` = ?,`headshots` = ?,`team_kills` = ?,`team_death` = ?,`max_kill_streak` = ?,`suicides` = ?,`rounds` = `rounds` + 1,`ratio` = ? WHERE `guid` = ?", values)
            conn.commit()

    def check_database(self):
        now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
        # check player table
        values = (self.guid,)
        curs.execute("SELECT COUNT(*) FROM `player` WHERE `guid` = ?", values)
        if curs.fetchone()[0] == 0:
            # add new player to database
            values = (self.guid, self.prettyname, self.address, now, self.prettyname)
            curs.execute("INSERT INTO `player` (`guid`,`name`,`ip_address`,`time_joined`,`aliases`) VALUES (?,?,?,?,?)", values)
            conn.commit()
            self.aliases.append(self.prettyname)
        else:
            # update name, IP address and last join date
            values = (self.prettyname, self.address, now, self.guid)
            curs.execute("UPDATE `player` SET `name` = ?,`ip_address` = ?,`time_joined` = ? WHERE `guid` = ?", values)
            conn.commit()
            # get known aliases
            values = (self.guid,)
            curs.execute("SELECT `aliases` FROM `player` WHERE `guid` = ?", values)
            result = curs.fetchone()
            # create list of aliases
            self.aliases = result[0].split(', ')
            if self.prettyname not in self.aliases:
                # add new alias to list
                if len(self.aliases) < 15:
                    self.aliases.append(self.prettyname)
                    alias_string = ', '.join(self.aliases)
                    values = (alias_string, self.guid)
                    curs.execute("UPDATE `player` SET `aliases` = ? WHERE `guid` = ?", values)
                    conn.commit()
        # get player-id
        values = (self.guid,)
        curs.execute("SELECT `id` FROM `player` WHERE `guid` = ?", values)
        self.player_id = curs.fetchone()[0]
        # check XLRSTATS table
        values = (self.guid,)
        curs.execute("SELECT COUNT(*) FROM `xlrstats` WHERE `guid` = ?", values)
        if curs.fetchone()[0] == 0:
            self.registered_user = False
        else:
            self.registered_user = True
            # get DB DATA for XLRSTATS
            values = (self.guid,)
            curs.execute("SELECT `last_played`,`num_played`,`kills`,`deaths`,`headshots`,`team_kills`,`team_death`,`max_kill_streak`,`suicides`,`admin_role`,`first_seen` FROM `xlrstats` WHERE `guid` = ?", values)
            result = curs.fetchone()
            self.last_visit = result[0]
            self.num_played = result[1]
            self.db_kills = result[2]
            self.db_deaths = result[3]
            self.db_head_shots = result[4]
            self.db_tk_count = result[5]
            self.db_team_death = result[6]
            self.db_killing_streak = result[7]
            self.db_suicide = result[8]
            self.admin_role = result[9]
            self.first_seen = result[10]
            # update name, last_played and increase num_played counter
            values = (self.prettyname, now, self.guid)
            curs.execute("UPDATE `xlrstats` SET `name` = ?,`last_played` = ?,`num_played` = `num_played` + 1 WHERE `guid` = ?", values)
            conn.commit()

    def define_offline_player(self, player_id):
        self.player_id = player_id
        values = (self.guid,)
        # get known aliases
        curs.execute("SELECT `aliases` FROM `player` WHERE `guid` = ?", values)
        result = curs.fetchone()
        # create list of aliases
        self.aliases = result[0].split(', ')
        curs.execute("SELECT COUNT(*) FROM `xlrstats` WHERE `guid` = ?", values)
        if curs.fetchone()[0] == 0:
            self.admin_role = 0
            self.registered_user = False
        else:
            curs.execute("SELECT `last_played`,`admin_role` FROM `xlrstats` WHERE `guid` = ?", values)
            result = curs.fetchone()
            self.last_visit = result[0]
            self.admin_role = result[1]
            self.registered_user = True

    def register_user_db(self, role=1):
        if not self.registered_user:
            now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
            values = (self.guid, self.prettyname, self.address, now, now, role)
            curs.execute("INSERT INTO `xlrstats` (`guid`,`name`,`ip_address`,`first_seen`,`last_played`,`num_played`,`admin_role`) VALUES (?,?,?,?,?,1,?)", values)
            conn.commit()
            self.registered_user = True
            self.admin_role = role
            self.welcome_msg = False
            self.first_seen = now
            self.last_visit = now

    def update_db_admin_role(self, role):
        values = (role, self.guid)
        curs.execute("UPDATE `xlrstats` SET `admin_role` = ? WHERE `guid` = ?", values)
        conn.commit()
        # overwrite admin role in game, no reconnect of player required
        self.set_admin_role(role)

    def get_ban_id(self):
        return self.ban_id

    def set_name(self, name):
        self.name = name.replace(' ', '')

    def get_name(self):
        return self.name

    def get_authname(self):
        return self.authname

    def get_aliases(self):
        if len(self.aliases) == 15:
            self.aliases.append("and more...")
        return str(", ^3".join(self.aliases))

    def set_guid(self, guid):
        self.guid = guid

    def get_guid(self):
        return self.guid

    def get_player_num(self):
        return self.player_num

    def get_player_id(self):
        return self.player_id

    def set_team(self, team):
        self.team = team

    def get_team(self):
        return self.team

    def get_team_lock(self):
        return self.team_lock

    def set_team_lock(self, team):
        self.team_lock = team

    def get_num_played(self):
        return self.num_played

    def get_last_visit(self):
        return str(self.last_visit)

    def get_first_seen_date(self):
        return str(self.first_seen)

    def get_db_kills(self):
        return self.db_kills

    def get_kills(self):
        return self.kills

    def get_db_deaths(self):
        return self.db_deaths

    def get_deaths(self):
        return self.deaths

    def get_db_headshots(self):
        return self.db_head_shots

    def get_headshots(self):
        return self.head_shots

    def disable_welcome_msg(self):
        self.welcome_msg = False

    def get_welcome_msg(self):
        return self.welcome_msg

    def get_country(self):
        return self.country

    def get_registered_user(self):
        return self.registered_user

    def set_admin_role(self, role):
        self.admin_role = role

    def get_admin_role(self):
        return self.admin_role

    def get_ip_address(self):
        return self.address

    def get_time_joined(self):
        return self.time_joined

    def get_max_kill_streak(self):
        return self.max_kill_streak

    def kill(self):
        self.killing_streak += 1
        self.kills += 1
        self.db_kills += 1

    def die(self):
        if self.killing_streak > self.max_kill_streak:
            self.max_kill_streak = self.killing_streak
        if self.max_kill_streak > self.db_killing_streak:
            self.db_killing_streak = self.max_kill_streak
        self.killing_streak = 0
        self.deaths += 1
        self.db_deaths += 1

    def suicide(self):
        self.db_suicide += 1

    def headshot(self):
        self.head_shots += 1
        self.db_head_shots += 1

    def set_hitzones(self, part):
        self.hitzone[part] += 1

    def get_hitzones(self, part):
        return self.hitzone[part]

    def set_all_hits(self):
        self.all_hits += 1

    def get_all_hits(self):
        return self.all_hits

    def set_he_kill(self):
        self.he_kills += 1

    def get_he_kills(self):
        return self.he_kills

    def set_knife_kill(self):
        self.knife_kills += 1

    def get_knife_kills(self):
        return self.knife_kills

    def get_killing_streak(self):
        return self.killing_streak

    def get_db_tks(self):
        return self.db_tk_count

    def get_team_kill_count(self):
        return self.tk_count

    def add_killed_me(self, killer):
        self.tk_killer_names.append(killer)

    def get_killed_me(self):
        return self.tk_killer_names

    def clear_killed_me(self, victim):
        while self.tk_victim_names.count(victim) > 0:
            self.tk_victim_names.remove(victim)

    def add_tk_victims(self, victim):
        self.tk_victim_names.append(victim)

    def get_tk_victim_names(self):
        return self.tk_victim_names

    def clear_tk(self, killer):
        while self.tk_killer_names.count(killer) > 0:
            self.tk_killer_names.remove(killer)

    def clear_all_tk(self):
        self.tk_killer_names = []

    def add_high_ping(self, value):
        self.warn_list.append('fix your ping')
        self.ping_value = value

    def get_ping_value(self):
        return self.ping_value

    def clear_specific_warning(self, warning):
        while self.warn_list.count(warning) > 0:
            self.warn_list.remove(warning)

    def add_warning(self, warning, timer=True):
        self.warn_list.append(warning)
        if timer:
            self.last_warn_time = time.time()

    def get_warning(self):
        return len(self.warn_list)

    def get_last_warn_msg(self):
        if len(self.warn_list) > 0:
            return self.warn_list[-1]

    def get_last_warn_time(self):
        return self.last_warn_time

    def clear_last_warning(self):
        if len(self.warn_list) > 0:
            last_warning = self.warn_list[-1]
            self.warn_list.pop()
            return last_warning

    def clear_warning(self):
        self.warn_list = []
        self.tk_victim_names = []
        self.tk_killer_names = []
        # clear ban_points
        now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
        values = (self.guid, now)
        curs.execute("DELETE FROM `ban_points` WHERE `guid` = ? and `expires` > ?", values)
        conn.commit()

    def team_death(self):
        # increase team death counter
        self.db_team_death += 1

    def team_kill(self):
        # increase teamkill counter
        self.tk_count += 1
        self.db_tk_count += 1

# CTF Mode
    def capture_flag(self):
        self.flags_captured += 1

    def get_flags_captured(self):
        return self.flags_captured

    def return_flag(self):
        self.flags_returned += 1

    def get_flags_returned(self):
        return self.flags_returned

    def set_flag_capture_time(self, cap_time):
        if cap_time < self.flag_capture_time:
            self.flag_capture_time = cap_time

    def get_flag_capture_time(self):
        if self.flag_capture_time == 999:
            return 0
        return self.flag_capture_time

# Bomb Mode
    def is_bombholder(self):
        self.bombholder = True

    def bomb_tossed(self):
        self.bombholder = False

    def get_bombholder(self):
        return self.bombholder

    def kill_bomb_carrier(self):
        self.bomb_carrier_killed += 1

    def get_bomb_carrier_kills(self):
        return self.bomb_carrier_killed

    def kills_with_bomb(self):
        self.killed_with_bomb += 1

    def get_kills_with_bomb(self):
        return self.killed_with_bomb

    def planted_bomb(self):
        self.bomb_planted += 1
        self.bombholder = False

    def get_planted_bomb(self):
        return self.bomb_planted

    def defused_bomb(self):
        self.bomb_defused += 1

    def get_defused_bomb(self):
        return self.bomb_defused

# Freeze Tag
    def freeze(self):
        self.froze += 1

    def get_freeze(self):
        return self.froze

    def thawout(self):
        self.thawouts += 1

    def get_thawout(self):
        return self.thawouts


### CLASS Game ###
class Game(object):
    """
    Game class
    """
    def __init__(self, config_file, urt_modversion):
        """
        create a new instance of Game

        @param config_file: The full path of the bot configuration file
        @type  config_file: String
        """
        self.all_maps_list = []
        self.next_mapname = ''
        self.mapname = ''
        self.maplist = []
        self.players = {}
        self.live = False
        self.urt_modversion = urt_modversion
        game_cfg = ConfigParser.ConfigParser()
        game_cfg.read(config_file)
        self.quake = PyQuake3("%s:%s" % (game_cfg.get('server', 'server_ip'), game_cfg.get('server', 'server_port')), game_cfg.get('server', 'rcon_password'))
        self.queue = Queue()
        self.rcon_lock = RLock()
        self.thread_rcon()
        logger.info("Opening RCON socket   : OK")

        # dynamic mapcycle
        self.dynamic_mapcycle = game_cfg.getboolean('mapcycle', 'dynamic_mapcycle') if game_cfg.has_option('mapcycle', 'dynamic_mapcycle') else False
        if self.dynamic_mapcycle:
            self.switch_count = game_cfg.getint('mapcycle', 'switch_count') if game_cfg.has_option('mapcycle', 'switch_count') else 4
            self.big_cycle = filter(None, game_cfg.get('mapcycle', 'big_cycle').replace(' ', '').split(',')) if game_cfg.has_option('mapcycle', 'big_cycle') else []
            self.small_cycle = filter(None, game_cfg.get('mapcycle', 'small_cycle').replace(' ', '').split(',')) if game_cfg.has_option('mapcycle', 'small_cycle') else []

        # add Spunky Bot as player 'World' to the game
        spunky_bot = Player(BOT_PLAYER_NUM, '127.0.0.1', 'NONE', 'World')
        self.add_player(spunky_bot)
        logger.info("Activating the Bot    : OK")
        logger.info("Startup completed     : Let's get ready to rumble!")
        logger.info("Spunky Bot is running until you are closing this session or pressing CTRL + C to abort this process.")
        logger.info("*** Note: Use the provided initscript to run Spunky Bot as daemon ***")

    def thread_rcon(self):
        """
        Thread process for starting method rcon_process
        """
        # start Thread
        processor = Thread(target=self.rcon_process)
        processor.setDaemon(True)
        processor.start()

    def rcon_process(self):
        """
        Thread process
        """
        while 1:
            if not self.queue.empty():
                if self.live:
                    with self.rcon_lock:
                        try:
                            command = self.queue.get()
                            if command != 'status':
                                self.quake.rcon(command)
                            else:
                                self.quake.rcon_update()
                        except Exception as err:
                            logger.error(err, exc_info=True)
                            #pass
            time.sleep(.33)

    def get_quake_value(self, value):
        """
        get Quake3 value
        """
        if self.live:
            with self.rcon_lock:
                self.quake.update()
                return self.quake.values[value]

    def get_rcon_output(self, value):
        """
        get RCON output for value
        """
        if self.live:
            with self.rcon_lock:
                return self.quake.rcon(value)

    def get_cvar(self, value):
        """
        get CVAR value
        """
        if self.live:
            with self.rcon_lock:
                try:
                    ret_val = self.quake.rcon(value)[1].split(':')[1].split('^7')[0].lstrip('"')
                except IndexError:
                    ret_val = None
                time.sleep(.33)
                return ret_val

    def get_mapcycle_path(self):
        """
        get the full path of mapcycle.txt file
        """
        maplist = []
        self.quake.rcon_update()
        # get path of fs_homepath and fs_basepath
        fs_homepath = self.get_cvar('fs_homepath')
        logger.debug("fs_homepath           : %s", fs_homepath)
        fs_basepath = self.get_cvar('fs_basepath')
        logger.debug("fs_basepath           : %s", fs_basepath)
        fs_game = self.get_cvar('fs_game')
        # get file name of mapcycle.txt
        mapcycle_file = self.get_cvar('g_mapcycle')
        try:
            # set full path of mapcycle.txt
            mc_home_path = os.path.join(fs_homepath, fs_game, mapcycle_file) if fs_homepath else ""
            mc_base_path = os.path.join(fs_basepath, fs_game, mapcycle_file) if fs_basepath else ""
        except TypeError:
            raise Exception('Server did not respond to mapcycle path request, please restart the Bot')
        if os.path.isfile(mc_home_path):
            mapcycle_path = mc_home_path
        elif os.path.isfile(mc_base_path):
            mapcycle_path = mc_base_path
        else:
            mapcycle_path = None
        if mapcycle_path:
            logger.info("Mapcycle path         : %s", mapcycle_path)
            with open(mapcycle_path, 'r') as file_handle:
                lines = [line for line in file_handle if line != '\n']
            try:
                while 1:
                    tmp = lines.pop(0).strip()
                    if tmp[0] == '{':
                        while tmp[0] != '}':
                            tmp = lines.pop(0).strip()
                        tmp = lines.pop(0).strip()
                    maplist.append(tmp)
            except IndexError:
                pass
        return maplist

    def send_rcon(self, command):
        """
        send RCON command

        @param command: The RCON command
        @type  command: String
        """
        if self.live:
            with self.rcon_lock:
                self.queue.put(command)

    def rcon_say(self, msg):
        """
        display message in global chat

        @param msg: The message to display in global chat
        @type  msg: String
        """
        # wrap long messages into shorter list elements
        lines = textwrap.wrap(msg, 140)
        for line in lines:
            self.send_rcon('say %s' % line)

    def rcon_tell(self, player_num, msg, pm_tag=True):
        """
        tell message to a specific player

        @param player_num: The player number
        @type  player_num: Integer
        @param msg: The message to display in private chat
        @type  msg: String
        @param pm_tag: Display '[pm]' (private message) in front of the message
        @type  pm_tag: bool
        """
        lines = textwrap.wrap(msg, 128)
        prefix = "^4[pm] "
        for line in lines:
            if pm_tag:
                self.send_rcon('tell %d %s%s' % (player_num, prefix, line))
                prefix = ""
            else:
                self.send_rcon('tell %d %s' % (player_num, line))

    def rcon_bigtext(self, msg):
        """
        display bigtext message

        @param msg: The message to display in global chat
        @type  msg: String
        """
        self.send_rcon('bigtext "%s"' % msg)

    def rcon_forceteam(self, player_num, team):
        """
        force player to given team

        @param player_num: The player number
        @type  player_num: Integer
        @param team: The team (red, blue, spectator)
        @type  team: String
        """
        self.send_rcon('forceteam %d %s' % (player_num, team))

    def rcon_clear(self):
        """
        clear RCON queue
        """
        self.queue.queue.clear()

    def kick_player(self, player_num, reason=''):
        """
        kick player

        @param player_num: The player number
        @type  player_num: Integer
        @param reason: Reason for kick
        @type  reason: String
        """
        if reason and self.urt_modversion > 41:
            self.send_rcon('kick %d "%s"' % (player_num, reason))
        else:
            self.send_rcon('kick %d' % player_num)

    def go_live(self):
        """
        go live
        """
        self.live = True
        self.set_all_maps()
        self.maplist = filter(None, self.get_mapcycle_path())
        self.set_current_map()
        self.rcon_say("^7Powered by ^8[Spunky Bot %s] ^1[www.spunkybot.de]" % __version__)
        logger.info("Mapcycle: %s", ', '.join(self.maplist))
        logger.info("*** Live tracking: Current map: %s / Next map: %s ***", self.mapname, self.next_mapname)
        logger.info("Server CVAR g_logsync : %s", self.get_cvar('g_logsync'))
        logger.info("Server CVAR g_loghits : %s", self.get_cvar('g_loghits'))

    def set_current_map(self):
        """
        set the current and next map in rotation
        """
        try:
            self.mapname = self.get_quake_value('mapname')
        except KeyError:
            self.mapname = self.next_mapname

        if self.dynamic_mapcycle:
            self.maplist = filter(None, (self.small_cycle if len(self.players) < (self.switch_count + 1) else self.big_cycle))
            logger.debug("Players online: %s / Mapcycle: %s", (len(self.players) - 1), self.maplist)

        if self.maplist:
            if self.mapname in self.maplist:
                if self.maplist.index(self.mapname) < (len(self.maplist) - 1):
                    self.next_mapname = self.maplist[self.maplist.index(self.mapname) + 1]
                else:
                    self.next_mapname = self.maplist[0]
            else:
                self.next_mapname = self.maplist[0]
        else:
            self.next_mapname = self.mapname

        logger.debug("Current map: %s / Next map: %s", self.mapname, self.next_mapname)

        if self.dynamic_mapcycle:
            self.send_rcon('g_nextmap %s' % self.next_mapname)

    def set_all_maps(self):
        """
        set a list of all available maps
        """
        all_maps = self.get_rcon_output("dir map bsp")[1].split()
        all_maps_list = [maps.replace("/", "").replace(".bsp", "") for maps in all_maps if maps.startswith("/")]
        pk3_list = self.get_rcon_output("fdir *.pk3")[1].split()
        all_pk3_list = [maps.replace("/", "").replace(".pk3", "").replace(".bsp", "") for maps in pk3_list if maps.startswith("/ut4_")]

        all_together = list(set(all_maps_list + all_pk3_list))
        all_together.sort()
        if all_together:
            self.all_maps_list = all_together

    def get_all_maps(self):
        """
        get a list of all available maps
        """
        return self.all_maps_list

    def add_player(self, player):
        """
        add a player to the game

        @param player: The instance of the player
        @type  player: Instance
        """
        self.players[player.get_player_num()] = player
        player.check_database()

    def get_gamestats(self):
        """
        get number of players in red team, blue team and spectator
        """
        game_data = {Player.teams[1]: 0, Player.teams[2]: 0, Player.teams[3]: 0}
        for player in self.players.itervalues():
            game_data[Player.teams[player.get_team()]] += 1
        return game_data

    def balance_teams(self, game_data):
        """
        balance teams if needed

        @param game_data: Dictionary of players in each team
        @type  game_data: dict
        """
        if (game_data[Player.teams[1]] - game_data[Player.teams[2]]) > 1:
            team1 = 1
            team2 = 2
        elif (game_data[Player.teams[2]] - game_data[Player.teams[1]]) > 1:
            team1 = 2
            team2 = 1
        else:
            self.rcon_say("^7Teams are already balanced")
            return
        self.rcon_bigtext("AUTOBALANCING TEAMS...")
        num_ptm = math.floor((game_data[Player.teams[team1]] - game_data[Player.teams[team2]]) / 2)
        player_list = [player for player in self.players.itervalues() if player.get_team() == team1 and not player.get_team_lock()]
        player_list.sort(cmp=lambda player1, player2: cmp(player2.get_time_joined(), player1.get_time_joined()))
        for player in player_list[:int(num_ptm)]:
            self.rcon_forceteam(player.get_player_num(), Player.teams[team2])
        self.rcon_say("^7Autobalance complete!")


### Main ###
# get full path of spunky.py
HOME = os.path.dirname(os.path.realpath(__file__))

# load the GEO database and store it globally in interpreter memory
GEOIP = pygeoip.Database(os.path.join(HOME, 'lib', 'GeoIP.dat'))

# connect to database
conn = sqlite3.connect(os.path.join(HOME, 'data.sqlite'))
curs = conn.cursor()

# create tables if not exists
curs.execute('CREATE TABLE IF NOT EXISTS xlrstats (id INTEGER PRIMARY KEY NOT NULL, guid TEXT NOT NULL, name TEXT NOT NULL, ip_address TEXT NOT NULL, first_seen DATETIME, last_played DATETIME, num_played INTEGER DEFAULT 1, kills INTEGER DEFAULT 0, deaths INTEGER DEFAULT 0, headshots INTEGER DEFAULT 0, team_kills INTEGER DEFAULT 0, team_death INTEGER DEFAULT 0, max_kill_streak INTEGER DEFAULT 0, suicides INTEGER DEFAULT 0, ratio REAL DEFAULT 0, rounds INTEGER DEFAULT 0, admin_role INTEGER DEFAULT 1)')
curs.execute('CREATE TABLE IF NOT EXISTS player (id INTEGER PRIMARY KEY NOT NULL, guid TEXT NOT NULL, name TEXT NOT NULL, ip_address TEXT NOT NULL, time_joined DATETIME, aliases TEXT)')
curs.execute('CREATE TABLE IF NOT EXISTS ban_list (id INTEGER PRIMARY KEY NOT NULL, guid TEXT NOT NULL, name TEXT, ip_address TEXT, expires DATETIME DEFAULT 259200, timestamp DATETIME, reason TEXT)')
curs.execute('CREATE TABLE IF NOT EXISTS ban_points (id INTEGER PRIMARY KEY NOT NULL, guid TEXT NOT NULL, point_type TEXT, expires DATETIME)')

# create instance of LogParser
LogParser(os.path.join(HOME, 'conf', 'settings.conf'))

# close database connection
conn.close()
