from django.db import models

# Create your models here.
class Vulnerability(models.Model):
    id = models.AutoField(primary_key=True)
    cve_id = models.CharField(max_length=20, unique=True)
    epss = models.CharField(max_length=20, null=True)
    cvss = models.CharField(max_length=20, null=True)
    cvss_version = models.CharField(max_length=20, null=True)
    attack_vector = models.CharField(max_length=40, null=True)
    pulses = models.IntegerField(default=0, null=True)
    date_discovered = models.DateField(default=None, null=True)
    KEV = models.BooleanField(default=False)
    exploit_db = models.BooleanField(default=False)

    class Meta:
      verbose_name_plural = "vulnerabilities"

    def __str__(self):
        return self.cve_id