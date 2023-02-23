from django.db import models

# Create your models here.
class Vulnerability(models.Model):
    id = models.AutoField(primary_key=True)
    cve_id = models.CharField(max_length=20, unique=True)
    epss = models.CharField(max_length=20)
    pulses = models.IntegerField(default=0, null=True)
    actively_exploited = models.BooleanField(default=False)
    date_discovered = models.DateField(default=None, null=True)
    latest_update = models.DateField(auto_now=True, null=True)
    
    class Meta:
      verbose_name_plural = "vulnerabilities"

    def __str__(self):
        return self.cve_id