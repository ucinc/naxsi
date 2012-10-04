from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.core.exceptions import ValidationError
from django.db.models import Q
import operator

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

class user_data(models.Manager):
    def get_query_set(self):
        return super(user_data, self).get_query_set()
    def allowed_data(self, request):
        allowed_files = request.user.get_profile().allowed_log_files.split('\r\n')
        mfilter = []
        for f in allowed_files:
            mfilter.append(Q(origin_log_file=f))
        return self.get_query_set().filter(reduce(operator.or_, mfilter))    
    


class nx_request(models.Model):
    raw_request_headers = models.TextField()
    raw_request_body = models.TextField()
    origin_log_file = models.TextField()
    date = models.DateTimeField('exception date')
    udata = user_data()
    objects = models.Manager()
    
class nx_fmt(models.Model):
    origin_log_file = models.TextField()
    date = models.DateTimeField('exception date')
    ip_client =  models.TextField()
    total_processed = models.IntegerField()
    total_blocked = models.IntegerField()
    learning_mode = models.BooleanField()

    false_positive = models.BooleanField()
    status_set_by_user = models.BooleanField()
    type = models.IntegerField(choices=InputType.TYPE)
    comment = models.TextField()

    server = models.TextField()
    uri = models.TextField()
    zone_raw = models.TextField()
    zone = models.IntegerField(choices=Zone.ZONES)
    zone_extra = models.IntegerField(choices=Zone.ZONE_EXTRA)
    nx_id = models.IntegerField()
    var_name = models.TextField()
    objects = models.Manager()
    udata = user_data()
    
    def __unicode__(self):
        return self.ip_client+str(self.total_processed)+str(self.total_blocked)


    class Meta:
        verbose_name = 'Import Log'
        verbose_name = 'Import Log'

def validate_path(value):
    if len(value.strip()) == 0:
        raise ValidationError("{0} is not a valid path to a logfile (the file must exist and the path must be absolute !)".format(filename))
    for filename in value.split('\n'):
        try:
            if len(filename) is 0:
                continue
            _ = open(filename.strip())
            _.close()
        except IOError:
            raise ValidationError("{0} is not a valid path to a logfile (the file must exist and the path must be absolute !)".format(filename))
        if not filename.strip().startswith('/'):
            raise ValidationError("{0} is not a valid path to a logfile (the file must exist and the path must be absolute !)".format(filename))     

class nx_user(models.Model):
    user = models.OneToOneField(User)
    allowed_log_files = models.TextField(validators=[validate_path])

    def save(self, *args, **kwargs):
        try:
            existing = nx_user.objects.get(user=self.user)
            self.id = existing.id
            self.user.is_staff = True
            self.user.save()
        except nx_user.DoesNotExist:
            pass 
        super(nx_user, self).save(*args, **kwargs)

    def __unicode__(self):
        return self.user.username

def create_user_profile(sender, instance, created, **kwargs):
    if created:
        nx_user.objects.get_or_create(user=instance)

post_save.connect(create_user_profile, sender=User)
