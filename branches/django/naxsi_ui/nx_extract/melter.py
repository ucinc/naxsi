
class Zone:
    ERROR=-1
    URL=0
    ARGS=1
    HEADERS=2
    BODY=3
    FILE_EXT=4
    REQUEST=5
    ALL=6
    NAME=0
    ZONES = ((-1,'ERROR'),
             (0,'URL'),
             (1,'ARGS'),
             (2, 'HEADERS'),
             (3, 'BODY'),
             (4, 'FILE_EXT'),
             (5, 'REQUEST'),
             (6, 'ALL'),)

    ZONE_EXTRA = ((-1, 'ERROR'),
                  (0, 'NAME'),)


class InputType:
    ERROR=-1
    EXCEPTION=0
    WHITELIST=1
    CR=2
    TYPE = ((-1, 'ERROR'),
            (0, 'EXCEPTION'),
            (1, 'WHITELIST'),
            (2, 'CR'),)

# class Types:
#     ERROR=0
#     EXCEPTION=1
#     WHITELIST=2
#     CR=3

# class Zone:

# class ZoneExtra:
#     ERROR="ERROR"
#     NAME="NAME"

# class Item:
#     item_type = Types.ERROR
#     origin_log_file = ""
#     date = ""
#     ip_client = ""
#     total_processed = 0
#     total_blocked = 0
#     learning_mode = 0
#     false_positive = False
#     status_set_by_user = False
#     comment = ""
#     server = ""
#     uri = ""
#     zone_raw = ""
#     zone = Zone.ERROR
#     zone_extra = ZoneExtra.ERROR
#     nx_id = -1
#     var_name = ""
#     # def sig_m(self, targ):
#     #     if self.nx_id != targ.nx_id:
#     #         return False
#     #     if self.zone != targ.zone:
#     #         return False
#     #     if self.zone_extra != targ.zone_extra:
#     #         return False
#     #     if self.
#     #     return True
#     # def full_m(self, targ):
#     #     if not sig_m(self, targ):
#     #         return False
#     #     if targ.date != self.date:
#     #         return False
#     #     if targ.ip_client != self.ip_client:
#     #         return False
#     #     if targ.total_processed != self.total_processed:
#     #         return False
#     #     if targ.total_blocked != self.total_blocked:
#     #         return False
#     #     return True
#     # def whitelist_m(self, targ):
#     #     return True
    
#     def __repr__(self):
#         r = "Item Type:"+str(self.item_type)
#         r += " Origin_log_file:"+self.origin_log_file
#         r += " Date:"+str(self.date)
#         r += " Ip:"+self.ip_client
#         r += " tp:"+str(self.total_processed)
#         r += " tb:"+str(self.total_blocked)
#         r += " learning:"+str(self.learning_mode)
#         r += " server:"+self.server
#         r += " uri:"+self.uri
#         r += " zone_raw:"+self.zone_raw
#         return r
    
        
        
