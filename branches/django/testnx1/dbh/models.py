from django.db import models


    
class nx_couples(models.Model):
    zone_raw = models.CharField(max_length=50)
    zone = models.CharField(max_length=50)
    nx_id = models.IntegerField()
    var_name = models.TextField()
    in_name = models.BooleanField()
    in_file = models.BooleanField()
    
    def __unicode__(self):
        return self.zone+self.id+self.var_name

# Create your models here.
class nx_fmts(models.Model):
    date = models.DateTimeField('exception date') 
    ip_client =  models.TextField()
    server = models.TextField()
    uri = models.TextField()
    total_processed = models.IntegerField()
    total_blocked = models.IntegerField()
    couples = models.ManyToManyField(nx_couples)
    learning_mode = models.BooleanField()
    false_positive = models.BooleanField()
    comment = models.TextField()
    
    def __unicode__(self):
        return self.date+self.ip_client+self.total_processed+self.total_blocked

