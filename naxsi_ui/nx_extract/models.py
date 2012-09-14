from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from  django.core.exceptions import ValidationError

ZONES = ((0,'URL'),
         (1,'ARGS'),
         (2, 'HEADERS'),
         (3, 'BODY'),
         (4, 'FILE_EXT'),
         (5, 'INTERNAL'),)

ZONE_EXTRA = ((0, 'NAME'),)

TYPE = ((0, 'EXCEPTION'),
        (1, 'WHITELIST'),
        (2, 'CR'),)

class nx_fmt(models.Model):
    origin_log_file = models.TextField()
    date = models.DateTimeField('exception date')
    ip_client =  models.TextField()
    total_processed = models.IntegerField()
    total_blocked = models.IntegerField()
    learning_mode = models.BooleanField()

    false_positive = models.BooleanField()
    status_set_by_user = models.BooleanField()
    type = models.IntegerField(choices=TYPE)
    comment = models.TextField()

    server = models.TextField()
    uri = models.TextField()
    zone = models.IntegerField(choices=ZONES)
    zone_extra = models.IntegerField(choices=ZONE_EXTRA)
    nx_id = models.IntegerField()
    var_name = models.TextField()

    
    def __unicode__(self):
        return str(self.date)+self.ip_client+str(self.total_processed)+str(self.total_blocked)


    class Meta:
        verbose_name = 'Import Log'
        verbose_name = 'Import Log'

def validate_path(value):
    if len(value.strip()) == 0:
        raise ValidationError("{0} is not a valid path to a logfile (the file must exist and the path must be absolute !)".format(filename))
    for filename in value.split('\n'):
        try:
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
