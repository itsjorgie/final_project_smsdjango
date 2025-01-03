# Generated by Django 3.2 on 2024-12-19 07:51

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('system1', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='sentmessage',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='system1_sent_messages', to=settings.AUTH_USER_MODEL),
        ),
        migrations.CreateModel(
            name='ReceivedMessage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('message', models.TextField()),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='system1_received_messages', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
